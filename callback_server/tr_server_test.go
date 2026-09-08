package callback_server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waas-api/api-sdk-go/crypto"
	"github.com/waas-api/api-sdk-go/travelrule"
)

const (
	testSeedB64         = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	testPubKeyB64       = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	testRemoteSeedB64   = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	testRemotePubKeyB64 = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="
)

func rsaPair(t *testing.T) (privatePem, publicPem string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	privateDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	publicDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDer})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDer}))
}

// memoryNonceStore is a test double only. Real deployments need shared storage,
// since a process local map cannot deduplicate across instances.
type memoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]bool
	fail error
}

func newMemoryNonceStore() *memoryNonceStore {
	return &memoryNonceStore{seen: map[string]bool{}}
}

func (s *memoryNonceStore) CheckAndMark(nonce string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if s.seen[nonce] {
		return errors.New("nonce already used")
	}
	s.seen[nonce] = true
	return nil
}

func (s *memoryNonceStore) contains(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[nonce]
}

// signedCallback builds a request signed the way the platform signs callbacks.
func signedCallback(t *testing.T, platformPrivatePem, path string, body []byte, nonce string, timestamp time.Time) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(timestamp.Unix(), 10)
	canonical := crypto.BuildRespCanonical(ts, nonce, crypto.AlgRsaSha256, crypto.Sha256Hex(body))
	signature, err := crypto.SignV2(canonical, crypto.AlgRsaSha256, platformPrivatePem)
	if err != nil {
		t.Fatalf("sign callback: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set(TrHeaderTimestamp, ts)
	req.Header.Set(TrHeaderNonce, nonce)
	req.Header.Set(TrHeaderSignAlg, crypto.AlgRsaSha256)
	req.Header.Set(TrHeaderSignature, signature)
	return req
}

func newTestServer(t *testing.T, platformPublicPem string, store NonceStore) *TrServer {
	t.Helper()
	signer, err := NewMemorySigner(testSeedB64)
	if err != nil {
		t.Fatalf("NewMemorySigner: %v", err)
	}
	server, err := NewTrServer(TrServerConfig{
		PlatformPublicKey: platformPublicPem,
		Signer:            signer,
		NonceStore:        store,
	})
	if err != nil {
		t.Fatalf("NewTrServer: %v", err)
	}
	return server
}

// A callback that fails verification must never reach the business function.
// This is the single most important property of the handlers: if it fails, an
// unauthenticated payload is being acted upon.
func TestBusinessFunctionNotCalledWhenVerificationFails(t *testing.T) {
	_, platformPublic := rsaPair(t)
	attackerPrivate, _ := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	called := false
	handler := server.HandleTransfer(func(TrTransferCallbackRequest) TrTransferCallbackResponse {
		called = true
		return TrTransferCallbackResponse{Result: TrResultVerified}
	})

	// Signed with a key the merchant does not trust.
	body := []byte(`{"vasp_id":"code:me","transfer_id":"t-1","result":"x"}`)
	req := signedCallback(t, attackerPrivate, TrPathTransfer, body, "0123456789abcdef", time.Now())
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Error("business function ran despite a failed signature verification")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestVerificationRejectsTamperedBody(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	// Sign one body, then deliver a different one under the same headers.
	signedBody := []byte(`{"vasp_id":"code:me","transfer_id":"t-1"}`)
	signed := signedCallback(t, platformPrivate, TrPathTransferResult, signedBody, "0123456789abcdef", time.Now())

	req := httptest.NewRequest(http.MethodPost, TrPathTransferResult,
		bytes.NewReader([]byte(`{"vasp_id":"code:me","transfer_id":"t-2"}`)))
	req.Header = signed.Header.Clone()

	called := false
	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		called = true
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Error("business function ran on a body that does not match its signature")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// An invalid request must not consume the nonce. Otherwise an attacker with no
// key could burn a chosen nonce and have the genuine callback rejected as a
// replay.
func TestInvalidSignatureDoesNotConsumeNonce(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	attackerPrivate, _ := rsaPair(t)
	store := newMemoryNonceStore()
	server := newTestServer(t, platformPublic, store)

	const targetNonce = "aaaabbbbccccdddd"
	body := []byte(`{"vasp_id":"code:me","transfer_id":"t-1"}`)

	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})

	// Poison attempt with a bad signature but the target nonce.
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, attackerPrivate, TrPathTransferResult, body, targetNonce, time.Now()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("poison attempt status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if store.contains(targetNonce) {
		t.Fatal("an unverified request consumed the nonce")
	}

	// The genuine callback with the same nonce must now succeed.
	rec = httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathTransferResult, body, targetNonce, time.Now()))
	if rec.Code != http.StatusOK {
		t.Errorf("genuine callback status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body)
	}
}

func TestReplayedNonceIsRejected(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	store := newMemoryNonceStore()
	server := newTestServer(t, platformPublic, store)

	body := []byte(`{"vasp_id":"code:me","transfer_id":"t-1"}`)
	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})

	req := signedCallback(t, platformPrivate, TrPathTransferResult, body, "0123456789abcdef", time.Now())
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first delivery status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Replay the identical request.
	replay := signedCallback(t, platformPrivate, TrPathTransferResult, body, "0123456789abcdef", time.Now())
	rec = httptest.NewRecorder()
	handler(rec, replay)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("replay status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// A nonce store outage must refuse the callback rather than let it through
// unchecked.
func TestNonceStoreFailureIsRejected(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	store := newMemoryNonceStore()
	store.fail = errors.New("redis unavailable")
	server := newTestServer(t, platformPublic, store)

	called := false
	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		called = true
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathTransferResult,
		[]byte(`{"transfer_id":"t-1"}`), "0123456789abcdef", time.Now()))

	if called {
		t.Error("business function ran while the nonce store was failing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// The timestamp window is checked in both directions. Without it, a replay
// stays possible indefinitely once the nonce record expires, because the
// signature itself never goes stale.
func TestTimestampWindowRejectsBothDirections(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	body := []byte(`{"transfer_id":"t-1"}`)
	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})

	tests := map[string]time.Time{
		"too old":       time.Now().Add(-DefaultTrTimestampWindow - time.Minute),
		"too far ahead": time.Now().Add(DefaultTrTimestampWindow + time.Minute),
	}
	for name, ts := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, signedCallback(t, platformPrivate, TrPathTransferResult, body, "0123456789abcdef", ts))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}

	// Just inside the window must be accepted.
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathTransferResult, body, "insidewindownonce",
		time.Now().Add(-DefaultTrTimestampWindow+30*time.Second)))
	if rec.Code != http.StatusOK {
		t.Errorf("in-window status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body)
	}
}

func TestMissingSignatureHeadersRejected(t *testing.T) {
	_, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, TrPathTransferResult, bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestNonPostRejected(t *testing.T) {
	_, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleHealth(func(TrHealthCallbackRequest) TrHealthCallbackResponse {
		return TrHealthCallbackResponse{Healthy: true}
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, TrPathHealth, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// The signature handler needs no business function: decode, sign, return.
func TestHandleSignatureSignsMessage(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	// Raw bytes ending in a big endian nonce, which is why the wire format is
	// base64: unencoded, those bytes would be mangled by JSON encoding.
	message := crypto.SigningMessage("2026-07-29T12:00:00+0000", []byte(`{"transferId":"t-1"}`), 0x01020304)
	requestBody, err := json.Marshal(TrSignatureRequest{
		VaspId:    "code:me",
		Message:   base64.StdEncoding.EncodeToString(message),
		Operation: "AssetTransferAuthorization",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	server.HandleSignature()(rec, signedCallback(t, platformPrivate, TrPathSignature, requestBody, "0123456789abcdef", time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body)
	}

	var response TrSignatureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// The signature must verify against the registered public key, which is what
	// the counterparty will check.
	if err := crypto.VerifyCodeVasp(message, response.Signature, testPubKeyB64); err != nil {
		t.Errorf("returned signature does not verify: %v", err)
	}
}

func TestHandleSignatureRejectsBadBase64(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	requestBody := []byte(`{"vasp_id":"code:me","message":"not base64!!!"}`)
	rec := httptest.NewRecorder()
	server.HandleSignature()(rec, signedCallback(t, platformPrivate, TrPathSignature, requestBody, "0123456789abcdef", time.Now()))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// Returning a value the platform does not accept would be turned into a denial
// with reason UNKNOWN there. Catching it locally keeps the cause visible.
func TestInvalidBusinessResultIsRejected(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleVerifyAddress(func(TrVerifyAddressCallbackRequest) TrVerifyAddressCallbackResponse {
		return TrVerifyAddressCallbackResponse{Result: "verified"} // wrong enum for this callback
	})
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathVerifyAddress,
		[]byte(`{"vasp_id":"code:me","possible_coins":["TRX","ETH"]}`), "0123456789abcdef", time.Now()))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// Inbound callbacks carry platform coin names, not the provider's currency, and
// no network field. The platform sends one exact coin when the provider supplies
// a network and a candidate list when it does not.
func TestInboundCallbacksCarryMappedCoinsAndNoNetwork(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	var verifyAddress TrVerifyAddressCallbackRequest
	verifyAddressHandler := server.HandleVerifyAddress(func(req TrVerifyAddressCallbackRequest) TrVerifyAddressCallbackResponse {
		verifyAddress = req
		return TrVerifyAddressCallbackResponse{Result: TrResultValid}
	})
	verifyAddressBody := []byte(`{"vasp_id":"code:me","possible_coins":["TRX","ETH"],"originator_vasp_id":"code:them","originator_public_key":"KeyA","payload":"Y2lwaGVy"}`)
	rec := httptest.NewRecorder()
	verifyAddressHandler(rec, signedCallback(t, platformPrivate, TrPathVerifyAddress, verifyAddressBody, "nonceverifyaddress1", time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("verifyAddress status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if !reflect.DeepEqual(verifyAddress.PossibleCoins, []string{"TRX", "ETH"}) {
		t.Errorf("verifyAddress possible_coins = %v, want [TRX ETH]", verifyAddress.PossibleCoins)
	}

	var transfer TrTransferCallbackRequest
	transferHandler := server.HandleTransfer(func(req TrTransferCallbackRequest) TrTransferCallbackResponse {
		transfer = req
		return TrTransferCallbackResponse{Result: TrResultVerified}
	})
	// A supplied network is consumed platform side to resolve one coin and is not
	// forwarded, so an unrecognised network field must not break decoding.
	body := []byte(`{"vasp_id":"code:me","transfer_id":"t-1","coin":"usdt_trc20","amount":"1.2","trade_price":"1.00","trade_currency":"USD","is_exceeding_threshold":true,"originator_vasp_id":"code:them","originator_public_key":"KeyA","payload":"Y2lwaGVy","beneficiary_address":"Tto","network":"TRON"}`)
	rec = httptest.NewRecorder()
	transferHandler(rec, signedCallback(t, platformPrivate, TrPathTransfer, body, "noncenoncetransfer1", time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if transfer.Coin != "usdt_trc20" {
		t.Errorf("coin = %q, want the platform coin name", transfer.Coin)
	}

	body = []byte(`{"vasp_id":"code:me","transfer_id":"t-2","possible_coins":["usdt_trc20","usdt_erc20"],"amount":"1.2","originator_vasp_id":"code:them","originator_public_key":"KeyA","payload":"Y2lwaGVy","beneficiary_address":"Tto"}`)
	rec = httptest.NewRecorder()
	transferHandler(rec, signedCallback(t, platformPrivate, TrPathTransfer, body, "noncenoncetransfer2", time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("candidate transfer status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if transfer.Coin != "" || !reflect.DeepEqual(transfer.PossibleCoins, []string{"usdt_trc20", "usdt_erc20"}) {
		t.Errorf("candidate transfer coins = coin %q, possible_coins %v", transfer.Coin, transfer.PossibleCoins)
	}

	// Asserted on the type rather than on marshalled output: an omitempty field
	// would be absent from the JSON whenever it happened to be empty, and the
	// check would pass either way.
	for _, callbackType := range []reflect.Type{
		reflect.TypeOf(TrTransferCallbackRequest{}),
		reflect.TypeOf(TrVerifyAddressCallbackRequest{}),
	} {
		for i := 0; i < callbackType.NumField(); i++ {
			if strings.HasPrefix(callbackType.Field(i).Tag.Get("json"), "network") {
				t.Errorf("%s declares a network field; the platform coin name already identifies the chain",
					callbackType.Name())
			}
		}
	}
}

func TestHandleAddressRegion(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	var received TrAddressRegionCallbackRequest
	handler := server.HandleAddressRegion(func(req TrAddressRegionCallbackRequest) TrAddressRegionCallbackResponse {
		received = req
		return TrAddressRegionCallbackResponse{Region: "KR"}
	})
	body := []byte(`{"vasp_id":"code:me","address":"12345","user_id":"user-1","contract":"xrp"}`)
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathAddressRegion, body,
		"nonceaddressregion", time.Now()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if received.VaspId != "code:me" || received.Address != "12345" ||
		received.UserId != "user-1" || received.Contract != "xrp" {
		t.Errorf("request fields lost: %+v", received)
	}
	if got, want := rec.Body.String(), `{"region":"KR","reason_message":""}`; got != want {
		t.Errorf("response = %s, want %s", got, want)
	}
}

func TestHandleAddressRegionAllowsUnknownRegion(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleAddressRegion(func(TrAddressRegionCallbackRequest) TrAddressRegionCallbackResponse {
		return TrAddressRegionCallbackResponse{ReasonMessage: "jurisdiction unavailable"}
	})
	body := []byte(`{"vasp_id":"code:me","address":"0xasdf123","contract":"eth"}`)
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathAddressRegion, body,
		"unknownaddrregion", time.Now()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Body.String(), `{"region":"","reason_message":"jurisdiction unavailable"}`; got != want {
		t.Errorf("response = %s, want %s", got, want)
	}
}

// Every callback response must name the reason field reason_message and nothing
// else. The platform reads only that name, so any other one loses the detail
// silently — no error, just an empty reason reaching the counterparty.
func TestCallbackResponsesUseReasonMessageOnly(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	const detail = "address book unavailable"
	cases := map[string]struct {
		handler http.HandlerFunc
		path    string
		body    string
	}{
		"verifyAddress": {
			handler: server.HandleVerifyAddress(func(TrVerifyAddressCallbackRequest) TrVerifyAddressCallbackResponse {
				return TrVerifyAddressCallbackResponse{
					Result: TrResultInvalid, ReasonType: TrReasonUnknown, ReasonMessage: detail,
				}
			}),
			path: TrPathVerifyAddress,
			body: `{"vasp_id":"code:me","possible_coins":["TRX","ETH"],"payload":"Y2lwaGVy"}`,
		},
		"transfer": {
			handler: server.HandleTransfer(func(TrTransferCallbackRequest) TrTransferCallbackResponse {
				return TrTransferCallbackResponse{
					Result: TrResultDenied, ReasonType: TrReasonUnknown, ReasonMessage: detail,
				}
			}),
			path: TrPathTransfer,
			body: `{"vasp_id":"code:me","transfer_id":"t-1","possible_coins":["usdt_trc20","usdt_erc20"],"payload":"Y2lwaGVy"}`,
		},
		"transferResult": {
			handler: server.HandleTransferResult(func(TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
				return TrTransferResultCallbackResponse{
					Result: TrResultError, ReasonType: TrReasonUnknown, ReasonMessage: detail,
				}
			}),
			path: TrPathTransferResult,
			body: `{"vasp_id":"code:me","transfer_id":"t-1","status":"confirmed","txid":"0xabc"}`,
		},
		"postTransfer": {
			handler: server.HandlePostTransfer(func(TrPostTransferCallbackRequest) TrPostTransferCallbackResponse {
				return TrPostTransferCallbackResponse{
					Result: TrResultError, ReasonType: TrReasonUnknown, ReasonMessage: detail,
				}
			}),
			path: TrPathPostTransfer,
			body: `{"vasp_id":"code:me","transfer_id":"t-1","txid":"0xabc","payload":"Y2lwaGVy"}`,
		},
		"addressRegion": {
			handler: server.HandleAddressRegion(func(TrAddressRegionCallbackRequest) TrAddressRegionCallbackResponse {
				return TrAddressRegionCallbackResponse{ReasonMessage: detail}
			}),
			path: TrPathAddressRegion,
			body: `{"vasp_id":"code:me","address":"0xasdf123","contract":"eth"}`,
		},
	}

	nonce := 0
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			nonce++
			rec := httptest.NewRecorder()
			test.handler(rec, signedCallback(t, platformPrivate, test.path, []byte(test.body),
				"noncenoncereason"+strconv.Itoa(nonce), time.Now()))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
			}
			got := rec.Body.String()
			if !strings.Contains(got, `"reason_message":"`+detail+`"`) {
				t.Errorf("response does not carry reason_message: %s", got)
			}
			if strings.Contains(got, "reason_msg\"") {
				t.Errorf("response carries reason_msg, which the platform does not read: %s", got)
			}
		})
	}
}

func TestHandleHealthReportsUnhealthyAs503(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleHealth(func(TrHealthCallbackRequest) TrHealthCallbackResponse {
		return TrHealthCallbackResponse{Healthy: false, Msg: "signer unreachable"}
	})
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathHealth,
		[]byte(`{"vasp_id":"code:me"}`), "0123456789abcdef", time.Now()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got, want := rec.Body.String(), `{"status":"ERROR"}`; got != want {
		t.Errorf("response = %s, want %s", got, want)
	}
}

func TestHandleHealthDefaultsToDocumentedStatus(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	handler := server.HandleHealth(func(TrHealthCallbackRequest) TrHealthCallbackResponse {
		return TrHealthCallbackResponse{Healthy: true}
	})
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathHealth,
		[]byte(`{"vasp_id":"code:me"}`), "healthycallback1", time.Now()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), `{"status":"OK"}`; got != want {
		t.Errorf("response = %s, want %s", got, want)
	}
}

// A signer switched to the wrong key still returns a signature, so health must
// verify it rather than only checking for an error.
func TestHealthCheckSignerDetectsWrongKey(t *testing.T) {
	_, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	if err := server.HealthCheckSigner(testPubKeyB64); err != nil {
		t.Errorf("HealthCheckSigner with the correct key: %v", err)
	}
	if err := server.HealthCheckSigner(testRemotePubKeyB64); err == nil {
		t.Error("HealthCheckSigner accepted a signer whose key does not match the registered one")
	}
}

func TestTransferResultDecodesDocumentedFields(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	var received TrTransferResultCallbackRequest
	handler := server.HandleTransferResult(func(req TrTransferResultCallbackRequest) TrTransferResultCallbackResponse {
		received = req
		return TrTransferResultCallbackResponse{Result: TrResultNormal}
	})

	body := []byte(`{"vasp_id":"code:me","transfer_id":"t-1","provider_transfer_id":"provider-1","status":"canceled","txid":"0xabc","vout":"0","reason_type":"UNKNOWN"}`)
	rec := httptest.NewRecorder()
	handler(rec, signedCallback(t, platformPrivate, TrPathTransferResult, body,
		"documentedresult", time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if received.VaspId != "code:me" || received.TransferId != "t-1" ||
		received.ProviderTransferId != "provider-1" || received.Status != "canceled" ||
		received.Txid != "0xabc" || received.Vout != "0" || received.ReasonType != TrReasonUnknown {
		t.Errorf("request fields lost: %+v", received)
	}
}

func TestCallbackSchemasMatchDocumentation(t *testing.T) {
	tests := []struct {
		name   string
		typeOf reflect.Type
		want   []string
	}{
		{"signature request", reflect.TypeOf(TrSignatureRequest{}), []string{"vasp_id", "message", "operation"}},
		{"signature response", reflect.TypeOf(TrSignatureResponse{}), []string{"signature"}},
		{"verifyAddress request", reflect.TypeOf(TrVerifyAddressCallbackRequest{}), []string{"vasp_id", "possible_coins", "originator_vasp_id", "originator_public_key", "payload"}},
		{"verifyAddress response", reflect.TypeOf(TrVerifyAddressCallbackResponse{}), []string{"result", "reason_type", "reason_message"}},
		{"transfer request", reflect.TypeOf(TrTransferCallbackRequest{}), []string{"vasp_id", "transfer_id", "provider_transfer_id", "coin", "possible_coins", "amount", "historical_cost", "trade_price", "trade_currency", "is_exceeding_threshold", "originating_vasp", "originator_vasp_id", "originator_public_key", "payload", "beneficiary_address", "tag"}},
		{"transfer response", reflect.TypeOf(TrTransferCallbackResponse{}), []string{"result", "reason_type", "reason_message", "beneficiary_address", "beneficiary_tag", "beneficiary_vasp", "payload", "originator_country_code", "beneficiary_country_code"}},
		{"transferResult request", reflect.TypeOf(TrTransferResultCallbackRequest{}), []string{"vasp_id", "transfer_id", "provider_transfer_id", "status", "txid", "vout", "reason_type"}},
		{"transferResult response", reflect.TypeOf(TrTransferResultCallbackResponse{}), []string{"result", "reason_type", "reason_message"}},
		{"postTransfer request", reflect.TypeOf(TrPostTransferCallbackRequest{}), []string{"vasp_id", "transfer_id", "provider_transfer_id", "txid", "beneficiary_address", "tag", "beneficiary_vasp_id", "beneficiary_public_key", "payload"}},
		{"postTransfer response", reflect.TypeOf(TrPostTransferCallbackResponse{}), []string{"result", "reason_type", "reason_message", "coin", "amount", "historical_cost", "trade_price", "trade_currency", "is_exceeding_threshold", "payload", "originator_country_code", "beneficiary_country_code"}},
		{"addressRegion request", reflect.TypeOf(TrAddressRegionCallbackRequest{}), []string{"vasp_id", "address", "user_id", "contract"}},
		{"addressRegion response", reflect.TypeOf(TrAddressRegionCallbackResponse{}), []string{"region", "reason_message"}},
		{"health request", reflect.TypeOf(TrHealthCallbackRequest{}), []string{"vasp_id"}},
		{"health response", reflect.TypeOf(TrHealthCallbackResponse{}), []string{"status"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got []string
			for i := 0; i < test.typeOf.NumField(); i++ {
				name := strings.Split(test.typeOf.Field(i).Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					got = append(got, name)
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("JSON fields = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCallbackResponsesKeepDocumentedEmptyFields(t *testing.T) {
	tests := []struct {
		name     string
		response any
		want     string
	}{
		{"verifyAddress", TrVerifyAddressCallbackResponse{}, `{"result":"","reason_type":"","reason_message":""}`},
		{"transfer", TrTransferCallbackResponse{}, `{"result":"","reason_type":"","reason_message":"","beneficiary_address":"","beneficiary_tag":"","beneficiary_vasp":null,"payload":"","originator_country_code":"","beneficiary_country_code":""}`},
		{"transferResult", TrTransferResultCallbackResponse{}, `{"result":"","reason_type":"","reason_message":""}`},
		{"postTransfer", TrPostTransferCallbackResponse{}, `{"result":"","reason_type":"","reason_message":"","coin":"","amount":"","historical_cost":"","trade_price":"","trade_currency":"","is_exceeding_threshold":false,"payload":"","originator_country_code":"","beneficiary_country_code":""}`},
		{"addressRegion", TrAddressRegionCallbackResponse{}, `{"region":"","reason_message":""}`},
		{"health", TrHealthCallbackResponse{}, `{"status":""}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.response)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if got := string(body); got != test.want {
				t.Errorf("response = %s, want %s", got, test.want)
			}
		})
	}
}

func TestNewTrServerValidation(t *testing.T) {
	_, publicPem := rsaPair(t)
	if _, err := NewTrServer(TrServerConfig{}); err == nil {
		t.Error("NewTrServer accepted a missing platform public key")
	}
	if _, err := NewTrServer(TrServerConfig{PlatformPublicKey: "not a pem"}); err == nil {
		t.Error("NewTrServer accepted a malformed platform public key")
	}
	server, err := NewTrServer(TrServerConfig{PlatformPublicKey: publicPem})
	if err != nil {
		t.Fatalf("NewTrServer: %v", err)
	}
	// Without a Signer the signature handler must fail rather than panic.
	rec := httptest.NewRecorder()
	server.HandleSignature()(rec, httptest.NewRequest(http.MethodPost, TrPathSignature, bytes.NewReader([]byte(`{}`))))
	if rec.Code == http.StatusOK {
		t.Error("signature handler succeeded without a Signer")
	}
}

func TestNewMemorySignerValidation(t *testing.T) {
	if _, err := NewMemorySigner(""); err == nil {
		t.Error("NewMemorySigner accepted an empty key")
	}
	if _, err := NewMemorySigner("not base64!!!"); err == nil {
		t.Error("NewMemorySigner accepted a malformed key")
	}
	if _, err := NewMemorySigner(base64.StdEncoding.EncodeToString(make([]byte, 20))); err == nil {
		t.Error("NewMemorySigner accepted a key of the wrong length")
	}
}

func TestPublicKeyMatchesSeed(t *testing.T) {
	got, err := PublicKey(testSeedB64)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if got != testPubKeyB64 {
		t.Errorf("public key = %q, want %q", got, testPubKeyB64)
	}
}

// A merchant decrypts an inbound payload and encrypts its reply for the same
// counterparty.
func TestCallbackPayloadRoundTrip(t *testing.T) {
	// The counterparty encrypts for the merchant.
	inbound, err := EncryptCallbackPayload(&travelrule.IVMS101{
		Originator: &travelrule.Originator{AccountNumber: []string{"Tfrom"}},
	}, testRemoteSeedB64, testPubKeyB64)
	if err != nil {
		t.Fatalf("EncryptCallbackPayload: %v", err)
	}

	// The merchant decrypts with its own key and the verified counterparty key.
	decrypted, err := DecryptCallbackPayload(inbound, testSeedB64, testRemotePubKeyB64)
	if err != nil {
		t.Fatalf("DecryptCallbackPayload: %v", err)
	}
	if decrypted.Originator == nil || len(decrypted.Originator.AccountNumber) != 1 {
		t.Fatalf("payload lost: %+v", decrypted)
	}

	// The merchant's reply must be readable by the counterparty.
	reply, err := EncryptCallbackPayload(&travelrule.IVMS101{
		Beneficiary: &travelrule.Beneficiary{AccountNumber: []string{"Tto"}},
	}, testSeedB64, testRemotePubKeyB64)
	if err != nil {
		t.Fatalf("encrypt reply: %v", err)
	}
	back, err := DecryptCallbackPayload(reply, testRemoteSeedB64, testPubKeyB64)
	if err != nil {
		t.Fatalf("counterparty could not decrypt the reply: %v", err)
	}
	if back.Beneficiary == nil || len(back.Beneficiary.AccountNumber) != 1 {
		t.Errorf("reply payload lost: %+v", back)
	}
}

func TestDecryptCallbackPayloadRejectsBadInput(t *testing.T) {
	if _, err := DecryptCallbackPayload("not base64!!!", testSeedB64, testRemotePubKeyB64); err == nil {
		t.Error("accepted a malformed base64 payload")
	}
	// Correct format, wrong key: box.Open must fail.
	sealed, err := EncryptCallbackPayloadBytes([]byte(`{}`), testRemoteSeedB64, testPubKeyB64)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptCallbackPayload(sealed, testSeedB64, testPubKeyB64); err == nil {
		t.Error("decrypted with the wrong counterparty key")
	}
}

// VerifyCallback is the entry point for merchants wiring callbacks into their
// own framework, so it must be usable and correct on its own.
func TestVerifyCallbackDirectUse(t *testing.T) {
	platformPrivate, platformPublic := rsaPair(t)
	server := newTestServer(t, platformPublic, newMemoryNonceStore())

	body := []byte(`{"vasp_id":"code:me"}`)
	req := signedCallback(t, platformPrivate, TrPathHealth, body, "0123456789abcdef", time.Now())
	if err := server.VerifyCallback(req.Header, body); err != nil {
		t.Errorf("VerifyCallback on a valid callback: %v", err)
	}
	if err := server.VerifyCallback(req.Header, []byte(`{"vasp_id":"code:other"}`)); err == nil {
		t.Error("VerifyCallback accepted a body that does not match the signature")
	}
}
