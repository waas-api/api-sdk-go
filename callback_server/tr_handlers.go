package callback_server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/waas-api/api-sdk-go/crypto"
)

// HandleSignature serves the signature callback.
//
// It takes no business function: the whole operation is decode the message,
// sign it, return the signature. The merchant does not need to know how the
// bytes were assembled, which removes any chance of assembling them differently
// from the platform.
//
// The Signer must be configured.
func (s *TrServer) HandleSignature() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		if s.conf.Signer == nil {
			s.reject(w, http.StatusInternalServerError, errors.New("no Signer configured"))
			return
		}
		var request TrSignatureRequest
		if !s.decode(w, body, &request) {
			return
		}
		// The message is base64 because the raw bytes end with a big endian
		// nonce that is usually not valid UTF-8; putting it in JSON unencoded
		// would silently replace those bytes.
		message, err := base64.StdEncoding.DecodeString(request.Message)
		if err != nil {
			s.reject(w, http.StatusBadRequest, fmt.Errorf("decode signature message: %w", err))
			return
		}
		signature, err := s.conf.Signer.Sign(message)
		if err != nil {
			s.reject(w, http.StatusInternalServerError, fmt.Errorf("sign message: %w", err))
			return
		}
		s.writeJson(w, TrSignatureResponse{Signature: signature})
	}
}

// HandleVerifyAddress serves the address verification callback.
//
// The business function decides whether the address belongs to one of the
// merchant's customers and returns TrResultValid or TrResultInvalid. The
// address is inside the encrypted payload, so decrypt it first with
// DecryptCallbackPayload.
func (s *TrServer) HandleVerifyAddress(
	business func(TrVerifyAddressCallbackRequest) TrVerifyAddressCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrVerifyAddressCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		response := business(request)
		if !s.checkResult(w, response.Result, TrResultValid, TrResultInvalid) {
			return
		}
		s.writeJson(w, response)
	}
}

// HandleTransfer serves the transfer authorisation callback.
//
// The business function decrypts the payload, runs KYC comparison and sanctions
// screening, and returns TrResultVerified or TrResultDenied together with its
// own encrypted payload. The counterparty is blocking on this answer, so keep
// it within the timeout.
func (s *TrServer) HandleTransfer(
	business func(TrTransferCallbackRequest) TrTransferCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrTransferCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		response := business(request)
		if !s.checkResult(w, response.Result, TrResultVerified, TrResultDenied) {
			return
		}
		s.writeJson(w, response)
	}
}

// HandleTransferResult serves the inbound transfer result callback, which
// reports a confirmed or canceled on-chain transfer.
//
// This one is retried more than once, and the protocol requires it to be
// idempotent: the same transfer id, status, txid and vout must always produce
// the same answer. Write the business function accordingly.
func (s *TrServer) HandleTransferResult(
	business func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrTransferResultCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		response := business(request)
		if !s.checkResult(w, response.Result, TrResultNormal, TrResultError) {
			return
		}
		s.writeJson(w, response)
	}
}

// HandlePostTransfer serves the supplementary data callback, which delivers
// identity data for a deposit that had already settled.
func (s *TrServer) HandlePostTransfer(
	business func(TrPostTransferCallbackRequest) TrPostTransferCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrPostTransferCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		response := business(request)
		if !s.checkResult(w, response.Result, TrResultNormal, TrResultError) {
			return
		}
		s.writeJson(w, response)
	}
}

// HandleAddressRegion serves the customer address jurisdiction callback.
//
// The business function should return the jurisdiction code associated with
// the address, or an empty Region when it cannot determine one. The platform
// does not retry this callback, so keep the lookup within its timeout.
func (s *TrServer) HandleAddressRegion(
	business func(TrAddressRegionCallbackRequest) TrAddressRegionCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrAddressRegionCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		s.writeJson(w, business(request))
	}
}

// HandleHealth serves the health probe, answering 200 when healthy and 503
// otherwise.
//
// The check must cover whether the signing dependency is available. Without
// that, the platform only finds out the signer is down when it needs a
// signature for a live compliance exchange. HealthCheckSigner does this check.
//
// The platform never retries this callback, precisely so that an intermittent
// fault is not smoothed over into apparent health.
func (s *TrServer) HandleHealth(
	business func(TrHealthCallbackRequest) TrHealthCallbackResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.readAndVerify(w, r)
		if !ok {
			return
		}
		var request TrHealthCallbackRequest
		if !s.decode(w, body, &request) {
			return
		}
		response := business(request)
		if !response.Healthy {
			s.logError(fmt.Errorf("health check reported unhealthy: %s", response.Msg))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			if response.Status == "" {
				response.Status = "ERROR"
			}
			body, err := json.Marshal(response)
			if err != nil {
				s.logError(fmt.Errorf("marshal health response: %w", err))
				return
			}
			_, _ = w.Write(body)
			return
		}
		if response.Status == "" {
			response.Status = "OK"
		}
		s.writeJson(w, response)
	}
}

// HealthCheckSigner reports whether the Signer can produce a valid signature.
//
// It signs a probe message and verifies the result against expectedPubKeyBase64,
// which must be the public key registered with the platform. Verifying rather
// than merely checking for an error catches a signer that has been switched to
// the wrong key: it would still return a signature, but not one the
// counterparty could verify.
func (s *TrServer) HealthCheckSigner(expectedPubKeyBase64 string) error {
	if s.conf.Signer == nil {
		return errors.New("no Signer configured")
	}
	probe := []byte("travel-rule signer health probe")
	signature, err := s.conf.Signer.Sign(probe)
	if err != nil {
		return fmt.Errorf("signer unavailable: %w", err)
	}
	if expectedPubKeyBase64 == "" {
		return nil
	}
	if err := crypto.VerifyCodeVasp(probe, signature, expectedPubKeyBase64); err != nil {
		return fmt.Errorf("signer produced a signature that does not match the registered public key: %w", err)
	}
	return nil
}
