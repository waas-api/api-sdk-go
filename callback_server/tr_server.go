package callback_server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/waas-api/api-sdk-go/crypto"
)

// v2 callback signature headers, set by the platform on every callback.
const (
	TrHeaderTimestamp = "X-Cbc-Timestamp"
	TrHeaderNonce     = "X-Cbc-Nonce"
	TrHeaderSignAlg   = "X-Cbc-Sign-Alg"
	TrHeaderSignature = "X-Cbc-Signature"
)

// DefaultTrTimestampWindow is the accepted clock skew for a callback. A
// timestamp window and nonce tracking are a pair: the window bounds how long a
// replay stays possible, and the nonce excludes repeats inside that span.
const DefaultTrTimestampWindow = 5 * time.Minute

// maxTrCallbackBodyBytes caps how much of a callback body is read, so an
// oversized request cannot exhaust memory.
const maxTrCallbackBodyBytes = 1 << 20

// Signer produces an Ed25519 signature over the exact bytes given.
//
// The private key never enters this SDK's configuration. In production, back
// this with an HSM or KMS. NewMemorySigner exists for tests and self managed
// keys.
//
// A sign-only implementation is enough for the signature callback, but it
// cannot decrypt payloads: NaCl box needs the raw key for scalar
// multiplication, which is not a signing operation. If the key must never leave
// the hardware, decryption has to happen there too.
type Signer interface {
	// Sign returns the standard base64 Ed25519 signature over message.
	Sign(message []byte) (signatureBase64 string, err error)
}

// NonceStore records callback nonces so a replayed callback can be rejected.
//
// There is deliberately no in-memory default: a process local map silently
// fails as soon as the callback endpoint runs more than one instance, which is
// the normal deployment. Back this with shared storage such as Redis SETNX.
type NonceStore interface {
	// CheckAndMark records nonce and returns an error if it was already
	// present. A storage failure should also be reported as an error, so the
	// callback is refused rather than accepted unchecked.
	CheckAndMark(nonce string, ttl time.Duration) error
}

// TrServerConfig configures a Travel Rule callback server.
type TrServerConfig struct {
	// PlatformPublicKey verifies callback signatures: PEM PKIX. Required.
	//
	// This is the public counterpart of the RSA key the platform holds for this
	// merchant, the same one used for v1 callbacks.
	PlatformPublicKey string
	// Signer signs CodeVASP request bytes. Required only if HandleSignature is
	// used.
	Signer Signer
	// NonceStore rejects replayed callbacks. Optional but strongly recommended;
	// when nil, replay protection is skipped and only the timestamp window
	// applies.
	NonceStore NonceStore
	// TimestampWindow is the accepted clock skew. Defaults to
	// DefaultTrTimestampWindow. Widening it widens the replay window by the
	// same amount.
	TimestampWindow time.Duration
	// ErrorLog receives rejection details. Optional.
	//
	// Rejections are otherwise invisible: the platform sees a 401 and reports a
	// callback failure, with no indication of which check failed.
	ErrorLog func(err error)
}

// TrServer verifies and dispatches Travel Rule callbacks.
//
// Each handler verifies the signature before decoding the body, and a failed
// verification never reaches the business function. Getting that order wrong is
// how an unauthenticated payload ends up being acted upon.
type TrServer struct {
	conf TrServerConfig
}

// NewTrServer builds a callback server.
func NewTrServer(config TrServerConfig) (*TrServer, error) {
	if config.PlatformPublicKey == "" {
		return nil, errors.New("PlatformPublicKey required")
	}
	if _, err := crypto.ParseRsaPublicKey(config.PlatformPublicKey); err != nil {
		return nil, fmt.Errorf("PlatformPublicKey invalid: %w", err)
	}
	if config.TimestampWindow <= 0 {
		config.TimestampWindow = DefaultTrTimestampWindow
	}
	return &TrServer{conf: config}, nil
}

// VerifyCallback checks a callback's signature headers against its body.
//
// Use it directly when wiring callbacks into a framework rather than through
// the handlers here. It performs, in order: timestamp window, signature
// verification, then nonce consumption.
//
// The nonce is consumed only after the signature verifies. Reversed, an
// attacker could burn a chosen nonce with an invalid signature and have the
// genuine callback rejected as a replay, needing no key at all.
func (s *TrServer) VerifyCallback(header http.Header, body []byte) error {
	timestamp := strings.TrimSpace(header.Get(TrHeaderTimestamp))
	nonce := strings.TrimSpace(header.Get(TrHeaderNonce))
	algorithm := strings.TrimSpace(header.Get(TrHeaderSignAlg))
	signature := strings.TrimSpace(header.Get(TrHeaderSignature))

	if timestamp == "" || nonce == "" || algorithm == "" || signature == "" {
		return errors.New("callback signature headers missing")
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("callback timestamp malformed: %w", err)
	}
	// Checked in both directions: a timestamp in the future would otherwise
	// stay valid far longer than the window.
	skew := time.Since(time.Unix(seconds, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > s.conf.TimestampWindow {
		return fmt.Errorf("callback timestamp outside the %s window", s.conf.TimestampWindow)
	}

	canonical := crypto.BuildRespCanonical(timestamp, nonce, algorithm, crypto.Sha256Hex(body))
	if err := crypto.VerifyV2(canonical, algorithm, s.conf.PlatformPublicKey, signature); err != nil {
		return fmt.Errorf("callback signature verification failed: %w", err)
	}

	if s.conf.NonceStore != nil {
		// Twice the window, so a callback near the future edge cannot outlive
		// its own nonce record and be replayed once the entry expires.
		if err := s.conf.NonceStore.CheckAndMark(nonce, 2*s.conf.TimestampWindow); err != nil {
			return fmt.Errorf("callback nonce rejected: %w", err)
		}
	}
	return nil
}

// readAndVerify reads the body and verifies it, writing an error response and
// returning ok=false when anything fails.
func (s *TrServer) readAndVerify(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	if r.Method != http.MethodPost {
		s.reject(w, http.StatusMethodNotAllowed, fmt.Errorf("callback method %s not allowed", r.Method))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTrCallbackBodyBytes+1))
	if err != nil {
		s.reject(w, http.StatusBadRequest, fmt.Errorf("read callback body: %w", err))
		return nil, false
	}
	if len(body) > maxTrCallbackBodyBytes {
		s.reject(w, http.StatusRequestEntityTooLarge, fmt.Errorf("callback body exceeds %d bytes", maxTrCallbackBodyBytes))
		return nil, false
	}
	if err := s.VerifyCallback(r.Header, body); err != nil {
		s.reject(w, http.StatusUnauthorized, err)
		return nil, false
	}
	return body, true
}

// reject reports a rejection without echoing details, which could confirm to a
// prober which check failed. The reason goes to ErrorLog instead.
func (s *TrServer) reject(w http.ResponseWriter, status int, err error) {
	s.logError(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"result":"error","reason_type":"` + TrReasonUnknown + `"}`))
}

func (s *TrServer) logError(err error) {
	if s.conf.ErrorLog != nil && err != nil {
		s.conf.ErrorLog(err)
	}
}

// writeJson sends a 200 response. The platform does not verify callback
// response signatures, so none is added; it only requires valid JSON and an
// allowed result value.
func (s *TrServer) writeJson(w http.ResponseWriter, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.reject(w, http.StatusInternalServerError, fmt.Errorf("marshal callback response: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// decode unmarshals a verified body.
func (s *TrServer) decode(w http.ResponseWriter, body []byte, out any) bool {
	if err := json.Unmarshal(body, out); err != nil {
		s.reject(w, http.StatusBadRequest, fmt.Errorf("decode callback body: %w", err))
		return false
	}
	return true
}

// checkResult guards against returning a value the platform will reject. An
// unrecognised result is turned into a denial with reason UNKNOWN on the
// platform side, so catching it here keeps the cause visible.
func (s *TrServer) checkResult(w http.ResponseWriter, result string, allowed ...string) bool {
	for _, candidate := range allowed {
		if result == candidate {
			return true
		}
	}
	s.reject(w, http.StatusInternalServerError,
		fmt.Errorf("business handler returned result %q, want one of %v", result, allowed))
	return false
}
