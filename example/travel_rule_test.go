package example

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/waas-api/api-sdk-go/callback_server"
	"github.com/waas-api/api-sdk-go/client"
	"github.com/waas-api/api-sdk-go/travelrule"
)

// Travel Rule example. These tests reach a live platform, so they are skipped
// unless the endpoints below are filled in; run them individually during
// integration.

var (
	// trClient talks to the v2 API. The RSA key is the same one used for v1.
	trClient client.ClientV2

	// trOwnVaspId is the merchant's own platform VASP id, formatted
	// {provider}:{provider_vasp_id}.
	trOwnVaspId = "code:merchant"

	// trEd25519PrivateKey is the base64 Ed25519 key the CodeVASP dashboard
	// issued: a 32 byte seed.
	//
	// This is a throwaway test key. In production the private key must live in
	// an approved HSM, KMS or key management system, and must never be placed in
	// a config file, log, ticket or chat message. The platform neither receives
	// nor stores it.
	trEd25519PrivateKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

func init() {
	c, err := client.NewClientV2(client.ConfigV2{
		AppId:      "asdfau9imt86qky9",
		KeyVersion: "admin",
		// The v2 prefix, not the v1 /shopapi base.
		BaseUrl:    "http://api.xxx.com/shopapi/v2",
		PrivateKey: privateKey,
		// Optional but recommended: verifies the response signature.
		PlatformPublicKey: platformPublicKey,
	})
	if err != nil {
		log.Println("travel rule client not configured:", err)
		return
	}
	trClient = c
}

func skipUnlessConfigured(t *testing.T) {
	t.Helper()
	if trClient == nil {
		t.Skip("travel rule client not configured")
	}
	t.Skip("fill in a real BaseUrl and credentials, then run this test individually")
}

// Step 1: fetch the directory and take the counterparty's public key from it.
//
// Cache the result and refresh periodically, but keep each key string exactly as
// received: it is case sensitive and must be echoed back byte for byte alongside
// any ciphertext it encrypted.
//
// The response is paged. Total counts everything matching the query, so page
// until the collected items reach it rather than until a page comes back short.
func Test_tr_VaspList(t *testing.T) {
	skipUnlessConfigured(t)

	var directory []client.TrVaspItem
	for page := 1; ; page++ {
		res, err := trClient.TrVaspList(context.TODO(), client.TrVaspListRequest{
			Page: page, PageSize: client.DefaultVaspPageSize,
		})
		if err != nil {
			t.Fatal("vaspList:", err)
		}
		directory = append(directory, res.Data.Items...)
		if len(res.Data.Items) == 0 || int64(len(directory)) >= res.Data.Total {
			break
		}
	}

	for _, vasp := range directory {
		// AllianceName decides which IVMS101 fields the counterparty requires.
		// Status is the platform's approval state; provider health is not exposed,
		// because a local snapshot of it would be stale and reads too easily as
		// "cleared to trade".
		t.Logf("%s (%s) alliance=%s status=%s keys=%d",
			vasp.VaspId, vasp.LegalName, vasp.AllianceName, vasp.Status, len(vasp.PublicKeys))
	}

	// Narrowing by name works too, for looking one counterparty up rather than
	// mirroring the whole directory.
	res, err := trClient.TrVaspList(context.TODO(), client.TrVaspListRequest{Keyword: "Upbit"})
	if err != nil {
		t.Fatal("vaspList by keyword:", err)
	}
	t.Logf("keyword search matched %d of %d", len(res.Data.Items), res.Data.Total)
}

// Step 2: find out which VASP owns a destination address.
//
// The first call almost always returns 618: the platform waits only a few
// seconds while the provider advises polling no more often than every 10
// seconds. That is a normal intermediate state, so retry the same call with the
// same parameters.
func Test_tr_VerifyAddress_Lookup(t *testing.T) {
	skipUnlessConfigured(t)

	request := client.TrVerifyAddressRequest{
		OriginatorVaspId: trOwnVaspId,
		// The platform coin name already identifies the chain, so there is no
		// network field: the platform resolves it from its own coin mapping.
		Coin:    "usdt_trc20",
		Address: "T...",
	}

	for attempt := 1; attempt <= 3; attempt++ {
		res, err := trClient.TrVerifyAddress(context.TODO(), request)
		if client.IsSearchProcessing(err) {
			t.Log("lookup still running, retrying in 12s")
			time.Sleep(12 * time.Second)
			continue
		}
		if err != nil {
			t.Fatal("verifyAddress:", err)
		}
		if res.Data.Result == client.ResultValid {
			// Feed this straight into the transfer request.
			t.Log("beneficiary vasp:", res.Data.BeneficiaryVaspId)
		} else {
			// Not found only means the address is unknown to the CODE network.
			// It does not imply the transfer is exempt from the Travel Rule.
			t.Log("not found:", res.Data.ReasonType, res.Data.ReasonMessage)
		}
		return
	}
	t.Log("no result after 3 attempts; the background poll will finish it")
}

// Step 3: submit the withdrawal.
func Test_tr_Transfer(t *testing.T) {
	skipUnlessConfigured(t)

	const beneficiaryVaspId = "code:beneficiary"
	// Taken from vaspList. Pass it through unchanged.
	const beneficiaryPubKey = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="

	// Build the identity document. The platform never sees this in plaintext, so
	// its completeness is the merchant's responsibility. Europe, Hong Kong and
	// GTR require a date of birth for natural persons.
	payload := &travelrule.IVMS101{
		Originator: &travelrule.Originator{
			OriginatorPersons: []travelrule.Person{{NaturalPerson: &travelrule.NaturalPerson{
				Name: &travelrule.NaturalPersonName{NameIdentifier: []travelrule.NaturalPersonNameID{{
					PrimaryIdentifier: "Doe", SecondaryIdentifier: "John", NameIdentifierType: "LEGL",
				}}},
				DateAndPlaceOfBirth: &travelrule.DateAndPlaceOfBirth{DateOfBirth: "1990-01-02"},
				CountryOfResidence:  "DE",
			}}},
			AccountNumber: []string{"Tfrom..."},
		},
		Beneficiary: &travelrule.Beneficiary{AccountNumber: []string{"Tto..."}},
	}

	encrypted, err := client.EncryptPayload(payload, trEd25519PrivateKey, beneficiaryPubKey)
	if err != nil {
		t.Fatal("encrypt payload:", err)
	}

	request := client.TrTransferRequest{
		OriginatorVaspId:   trOwnVaspId,
		BeneficiaryVaspId:  beneficiaryVaspId,
		ShopOrderId:        "merchant-order-1",
		Coin:               "usdt_trc20",
		Amount:             "1.2",
		TradePrice:         "1.00",
		TradeCurrency:      "USD",
		OriginatorAddress:  "Tfrom...",
		BeneficiaryAddress: "Tto...",
		BeneficiaryType:    client.BeneficiaryTypeVasp,
		// KYC country of the sending wallet's owner. The platform records it
		// without validating ownership.
		OriginatorCountryCode: "DE",
	}
	// The merchant decides the threshold question; the platform only keeps the
	// record. All of these fields are needed to explain the decision afterwards.
	//
	// SetThresholdExceeded(true) is also accepted, but a bare boolean cannot
	// answer which jurisdiction and rule version the decision rested on, so the
	// platform marks such records as carrying incomplete evidence.
	request.SetThreshold(client.TrThresholdDeclaration{
		Exceeded:     client.NewThresholdExceeded(true),
		Jurisdiction: "EU",
		RuleVersion:  "2026-01",
		Value:        "1000",
		Currency:     "EUR",
		FiatAmount:   "1.20",
		DecidedAt:    time.Now().Unix(),
	})
	// Sets the ciphertext and the key that produced it together, so they cannot
	// diverge.
	encrypted.ApplyToTransfer(&request)

	res, err := trClient.TrTransfer(context.TODO(), request)
	if err != nil {
		t.Fatal("transfer:", err)
	}

	// Result alone decides whether to proceed: it is only ever verified or
	// denied, with PASS reporting verified and MANUAL reporting denied.
	if res.Data.Result != client.ResultVerified {
		t.Log("not cleared to send:", res.Data.ReasonType, res.Data.ReasonMessage)
		return
	}

	// RouteDecision explains why, which is what distinguishes an actual refusal
	// from the platform holding the transfer for review.
	switch res.Data.RouteDecision {
	case client.RouteDecisionTrCode:
		if res.Data.Payload != "" {
			// The counterparty's identity data, still encrypted.
			counterparty, err := client.DecryptPayload(res.Data.Payload, trEd25519PrivateKey, beneficiaryPubKey)
			if err != nil {
				t.Fatal("decrypt response payload:", err)
			}
			bs, _ := json.MarshalIndent(counterparty, "", "\t")
			t.Log("counterparty identity:\n", string(bs))
		}
		if len(res.Data.BeneficiaryVasp) > 0 {
			// An optional override of the beneficiaryVasp object. When present it
			// takes precedence over the same content inside the payload; the
			// platform passes it through without parsing.
			t.Log("beneficiary vasp override:", string(res.Data.BeneficiaryVasp))
		}
	case client.RouteDecisionPass:
		// No exchange was needed, and the assessment is on record either way.
		t.Log("released without an exchange:", res.Data.ReasonMessage)
	}
}

// Unattributed deposit: look up who sent it, then supply the missing data.
func Test_tr_QueryTransfer_And_PostTransfer(t *testing.T) {
	skipUnlessConfigured(t)

	// No network field here: the coin name carries the chain.
	query, err := trClient.TrQueryTransfer(context.TODO(), client.TrQueryTransferRequest{
		Coin:               "usdt_trc20",
		Txid:               "abc...",
		BeneficiaryAddress: "Tto...",
	})
	if client.IsSearchProcessing(err) {
		t.Skip("lookup still running, retry after 10s or more")
	}
	if err != nil {
		t.Fatal("queryTransfer:", err)
	}

	// Encrypt for the key the lookup reported. OriginatorPubKeys holds every key
	// the platform knows for that VASP, for retrying through a key rotation.
	encrypted, err := client.EncryptPayload(&travelrule.IVMS101{
		Beneficiary: &travelrule.Beneficiary{AccountNumber: []string{"Tto..."}},
	}, trEd25519PrivateKey, query.Data.OriginatorPubKey)
	if err != nil {
		t.Fatal("encrypt payload:", err)
	}

	// Locate the completed queryTransfer by the same txid and coin. RequestId from
	// the lookup is only for troubleshooting; the platform fills CodeVASP's
	// reverse-lookup id from its task table.
	request := client.TrPostTransferRequest{
		VaspId:             trOwnVaspId,
		Txid:               "abc...",
		Coin:               "usdt_trc20",
		BeneficiaryAddress: "Tto...",
	}
	// TrQueryTransfer must have run first: this endpoint never starts a lookup of
	// its own, and answers 615 when there is no result to reuse.
	encrypted.ApplyToPostTransfer(&request)

	res, err := trClient.TrPostTransfer(context.TODO(), request)
	if err != nil {
		t.Fatal("postTransfer:", err)
	}
	// TransferId is the platform-local id for this submission. Coin and Contract
	// are platform names, matching what requests take.
	t.Logf("postTransfer %s: %s %s %s exceeded=%t",
		res.Data.TransferId, res.Data.Result, res.Data.Coin, res.Data.Amount, res.Data.IsExceedingThreshold)
}

// redisNonceStore sketches the replay protection a merchant must supply.
//
// Back it with shared storage. A process local map silently stops working as
// soon as the callback endpoint runs more than one instance, which is the normal
// deployment.
type redisNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (s *redisNonceStore) CheckAndMark(nonce string, ttl time.Duration) error {
	// Real implementation: SETNX key with the given TTL, returning an error both
	// when the key exists and when the store is unreachable. Refusing on a store
	// failure is deliberate: accepting unchecked callbacks would be worse.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if expiry, ok := s.seen[nonce]; ok && time.Now().Before(expiry) {
		return errors.New("nonce already used")
	}
	s.seen[nonce] = time.Now().Add(ttl)
	return nil
}

// The six endpoints a merchant exposes. Signature verification happens inside
// each handler, and a failed verification never reaches the business function.
func Test_tr_CallbackServer(t *testing.T) {
	t.Skip("run this manually to serve Travel Rule callbacks")

	// Production: implement Signer against an HSM or KMS instead.
	//
	// Note the asymmetry: a sign-only HSM is enough for the signature callback,
	// but it cannot decrypt payloads, because NaCl box needs the raw key rather
	// than a signing operation. If the key must never leave the hardware,
	// decryption has to happen inside it too.
	signer, err := callback_server.NewMemorySigner(trEd25519PrivateKey)
	if err != nil {
		t.Fatal("signer:", err)
	}

	server, err := callback_server.NewTrServer(callback_server.TrServerConfig{
		// The public counterpart of the RSA key the platform holds for this
		// merchant: the same key as v1 callbacks.
		PlatformPublicKey: platformPublicKey,
		Signer:            signer,
		NonceStore:        &redisNonceStore{},
		ErrorLog: func(err error) {
			// Rejections are otherwise invisible: the platform only sees a 401.
			log.Println("travel rule callback rejected:", err)
		},
	})
	if err != nil {
		t.Fatal("callback server:", err)
	}

	mux := http.NewServeMux()

	// Called before every outbound CodeVASP request, including each poll of an
	// in-flight lookup. Around 100 concurrent lookups produce roughly 10 calls
	// per second, so size for that. No business function: the SDK decodes,
	// signs and answers.
	mux.Handle(callback_server.TrPathSignature, server.HandleSignature())

	// Is this address one of ours? The address is inside the encrypted payload.
	mux.Handle(callback_server.TrPathVerifyAddress, server.HandleVerifyAddress(
		func(req callback_server.TrVerifyAddressCallbackRequest) callback_server.TrVerifyAddressCallbackResponse {
			// Decrypt with the key the platform supplied: that is the key it
			// verified the inbound request against, not the untrusted header value.
			payload, err := callback_server.DecryptCallbackPayload(
				req.Payload, trEd25519PrivateKey, req.OriginatorPublicKey)
			if err != nil {
				log.Println("decrypt payload:", err)
				return callback_server.TrVerifyAddressCallbackResponse{
					Result:        callback_server.TrResultInvalid,
					ReasonType:    callback_server.TrReasonUnknown,
					ReasonMessage: "could not decrypt the payload",
				}
			}
			// req.Coin is the platform coin name, the same form the outbound API
			// takes, so it can go straight into your own coin table. There is no
			// network field: the name already identifies the chain.
			_ = req.Coin
			_ = payload // look the account number up in your own address book
			return callback_server.TrVerifyAddressCallbackResponse{Result: callback_server.TrResultValid}
		}))

	// Authorise an incoming transfer. The counterparty is blocking on this.
	mux.Handle(callback_server.TrPathTransfer, server.HandleTransfer(
		func(req callback_server.TrTransferCallbackRequest) callback_server.TrTransferCallbackResponse {
			payload, err := callback_server.DecryptCallbackPayload(
				req.Payload, trEd25519PrivateKey, req.OriginatorPublicKey)
			if err != nil {
				return callback_server.TrTransferCallbackResponse{
					Result: callback_server.TrResultDenied, ReasonType: callback_server.TrReasonUnknown,
				}
			}
			_ = payload // run KYC comparison and sanctions screening here

			// Reply with your own identity data, encrypted for the originator.
			reply, err := callback_server.EncryptCallbackPayload(&travelrule.IVMS101{
				Beneficiary: &travelrule.Beneficiary{AccountNumber: []string{req.BeneficiaryAddress}},
			}, trEd25519PrivateKey, req.OriginatorPublicKey)
			if err != nil {
				return callback_server.TrTransferCallbackResponse{
					Result: callback_server.TrResultDenied, ReasonType: callback_server.TrReasonUnknown,
				}
			}
			return callback_server.TrTransferCallbackResponse{
				Result:  callback_server.TrResultVerified,
				Payload: reply,
			}
		}))

	// Final outcome. This one is retried, and the protocol requires idempotency:
	// the same transfer id, status, txid and vout must always answer the same.
	//
	// Two different flows arrive here, carrying different fields.
	mux.Handle(callback_server.TrPathTransferResult, server.HandleTransferResult(
		func(req callback_server.TrTransferResultCallbackRequest) callback_server.TrTransferResultCallbackResponse {
			if req.IsOutboundAuthorization() {
				// The authorisation conclusion for one of our own withdrawals.
				log.Printf("withdrawal %s authorisation=%s %s",
					req.TransferId, req.Result, req.ReasonMessage)
				if req.Payload != "" {
					// The counterparty's identity data, encrypted for the key we
					// used on the transfer.
					_ = req.Payload
				}
			} else {
				// An inbound on-chain result forwarded from the counterparty.
				log.Printf("transfer %s status=%s txid=%s", req.TransferId, req.Status, req.Txid)
			}
			return callback_server.TrTransferResultCallbackResponse{Result: callback_server.TrResultNormal}
		}))

	// Identity data for a deposit that had already settled.
	mux.Handle(callback_server.TrPathPostTransfer, server.HandlePostTransfer(
		func(req callback_server.TrPostTransferCallbackRequest) callback_server.TrPostTransferCallbackResponse {
			payload, err := callback_server.DecryptCallbackPayload(
				req.Payload, trEd25519PrivateKey, req.BeneficiaryPublicKey)
			if err != nil {
				return callback_server.TrPostTransferCallbackResponse{
					Result: callback_server.TrResultError, ReasonType: callback_server.TrReasonUnknown,
				}
			}
			_ = payload // record it against the deposit

			// Optionally echo the transaction details back. Coin takes the platform
			// name, as everywhere else; the platform maps it to the provider's
			// currency before answering the counterparty.
			return callback_server.TrPostTransferCallbackResponse{
				Result: callback_server.TrResultNormal,
				Coin:   "usdt_trc20",
				Amount: "1.2",
			}
		}))

	// Health must include the signing dependency. Without it, the platform only
	// discovers a broken signer when a live compliance exchange needs one.
	mux.Handle(callback_server.TrPathHealth, server.HandleHealth(
		func(callback_server.TrHealthCallbackRequest) callback_server.TrHealthCallbackResponse {
			ownPubKey, err := callback_server.PublicKey(trEd25519PrivateKey)
			if err != nil {
				return callback_server.TrHealthCallbackResponse{Healthy: false, Msg: err.Error()}
			}
			if err := server.HealthCheckSigner(ownPubKey); err != nil {
				return callback_server.TrHealthCallbackResponse{Healthy: false, Msg: err.Error()}
			}
			return callback_server.TrHealthCallbackResponse{Healthy: true}
		}))

	log.Println("serving travel rule callbacks on :8081")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatal(err)
	}
}
