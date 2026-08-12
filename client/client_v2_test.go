package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/waas-api/api-sdk-go/crypto"
	"github.com/waas-api/api-sdk-go/travelrule"
)

func rsaKeyPairPem(t *testing.T, bits int) (privatePem, publicPem string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
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

// capturedRequest records what the server actually received, so tests can
// assert on the exact bytes rather than on what the client believes it sent.
type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// newFakePlatform stands in for the platform. It verifies the request signature
// the same way the middleware does and signs its response, so the test exercises
// the real agreement between the two sides.
func newFakePlatform(t *testing.T, merchantPublicPem, platformPrivatePem string, responseData any) (*httptest.Server, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		captured.method = r.Method
		captured.path = r.URL.EscapedPath()
		captured.headers = r.Header.Clone()
		captured.body = body

		keyVersion := r.Header.Get(HeaderKeyVersion)
		if keyVersion == "" {
			keyVersion = DefaultKeyVersion
		}
		canonical := crypto.SignV2Params{
			Method:        r.Method,
			Path:          r.URL.EscapedPath(),
			AppId:         r.Header.Get(HeaderAppId),
			KeyVersion:    keyVersion,
			Timestamp:     r.Header.Get(HeaderTimestamp),
			Nonce:         r.Header.Get(HeaderNonce),
			BodySha256Hex: crypto.Sha256Hex(body),
		}.Canonical()
		if err := crypto.VerifyV2(canonical, r.Header.Get(HeaderSignAlg), merchantPublicPem, r.Header.Get(HeaderSignature)); err != nil {
			// Mirror the platform: an unverified request is refused before any
			// business handling, and the error response carries no signature.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":605,"msg":"signature verification failed"}`))
			return
		}

		respBody, err := json.Marshal(map[string]any{
			"status": 200, "msg": "请求成功", "data": responseData,
			"date_time": "2026-07-29 12:00:00", "time_stamp": 1785297600,
		})
		if err != nil {
			t.Errorf("marshal response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		signResponse(t, w, platformPrivatePem, respBody)
	}))
	t.Cleanup(server.Close)
	return server, captured
}

func signResponse(t *testing.T, w http.ResponseWriter, platformPrivatePem string, body []byte) {
	t.Helper()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "0123456789abcdef0123456789abcdef"
	canonical := crypto.BuildRespCanonical(timestamp, nonce, crypto.AlgRsaSha256, crypto.Sha256Hex(body))
	signature, err := crypto.SignV2(canonical, crypto.AlgRsaSha256, platformPrivatePem)
	if err != nil {
		t.Errorf("sign response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(HeaderTimestamp, timestamp)
	w.Header().Set(HeaderNonce, nonce)
	w.Header().Set(HeaderSignAlg, crypto.AlgRsaSha256)
	w.Header().Set(HeaderSignature, signature)
	_, _ = w.Write(body)
}

func newTestClient(t *testing.T, baseUrl, merchantPrivatePem, platformPublicPem string) ClientV2 {
	t.Helper()
	c, err := NewClientV2(ConfigV2{
		AppId:             "testapp",
		BaseUrl:           baseUrl,
		PrivateKey:        merchantPrivatePem,
		PlatformPublicKey: platformPublicPem,
	})
	if err != nil {
		t.Fatalf("NewClientV2: %v", err)
	}
	return c
}

// The signature covers a digest of the body, so the bytes sent must be exactly
// the bytes hashed. Re-serializing after signing would break every request, and
// only in production.
func TestClientV2SendsExactlyTheBytesItSigned(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)
	server, captured := newFakePlatform(t, merchantPublic, platformPrivate, map[string]any{
		"transfer_id": "t-1", "route_decision": RouteDecisionTrCode, "result": ResultVerified,
	})

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	request := TrTransferRequest{
		OriginatorVaspId: "code:me", BeneficiaryVaspId: "code:them",
		Coin: "usdt_trc20", Amount: "1.20", TradePrice: "1.00", TradeCurrency: "USD",
		OriginatorAddress: "Tfrom", BeneficiaryAddress: "Tto",
		BeneficiaryType: BeneficiaryTypeVasp,
	}
	request.SetThreshold(TrThresholdDeclaration{
		Exceeded: NewThresholdExceeded(true), Jurisdiction: "EU", RuleVersion: "2026-01",
		Value: "1000", Currency: "EUR", FiatAmount: "1.20", DecidedAt: time.Now().Unix(),
	})
	_, err := c.TrTransfer(context.Background(), request)
	if err != nil {
		t.Fatalf("TrTransfer: %v", err)
	}

	// The fake platform verified the signature against the body it received, so
	// reaching here already proves the bytes match. Assert the digest too, so a
	// failure names the cause instead of just reporting 605.
	gotDigest := crypto.Sha256Hex(captured.body)
	canonical := crypto.SignV2Params{
		Method: captured.method, Path: captured.path,
		AppId:         captured.headers.Get(HeaderAppId),
		KeyVersion:    captured.headers.Get(HeaderKeyVersion),
		Timestamp:     captured.headers.Get(HeaderTimestamp),
		Nonce:         captured.headers.Get(HeaderNonce),
		BodySha256Hex: gotDigest,
	}.Canonical()
	if err := crypto.VerifyV2(canonical, crypto.AlgRsaSha256, merchantPublic, captured.headers.Get(HeaderSignature)); err != nil {
		t.Errorf("signature does not cover the body as received: %v", err)
	}

	// Amount must survive as the string given: "1.20" must not become 1.2.
	if !strings.Contains(string(captured.body), `"amount":"1.20"`) {
		t.Errorf("amount was reformatted on the wire: %s", captured.body)
	}
}

// emptyVaspPage is what the platform answers for a query that matches nothing:
// a paging envelope with an empty items array, not a bare array.
func emptyVaspPage() map[string]any {
	return map[string]any{"items": []any{}, "page": 1, "page_size": DefaultVaspPageSize, "total": 0}
}

// The signed path must be the escaped path only, with no host and no query.
func TestClientV2SignsEscapedPathOnly(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)
	server, captured := newFakePlatform(t, merchantPublic, platformPrivate, emptyVaspPage())

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{}); err != nil {
		t.Fatalf("TrVaspList: %v", err)
	}
	if captured.path != "/shopapi/v2/travelRule/vaspList" {
		t.Errorf("unexpected signed path: %q", captured.path)
	}
	if captured.method != http.MethodPost {
		t.Errorf("expected POST, got %s", captured.method)
	}
}

// Every vaspList field is optional, so an empty request must serialize as {} and
// still be signed. All four are omitempty, which is what keeps the platform's
// defaults in charge rather than sending page=0.
func TestClientV2VaspListSendsEmptyObject(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)
	server, captured := newFakePlatform(t, merchantPublic, platformPrivate, map[string]any{
		"items": []any{
			map[string]any{"vasp_id": "code:them", "name": "Them", "alliance_name": "code"},
		},
		"page": 1, "page_size": DefaultVaspPageSize, "total": 1,
	})

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	res, err := c.TrVaspList(context.Background(), TrVaspListRequest{})
	if err != nil {
		t.Fatalf("TrVaspList: %v", err)
	}
	if string(captured.body) != "{}" {
		t.Errorf("expected body {}, got %s", captured.body)
	}
	if len(res.Data.Items) != 1 || res.Data.Items[0].VaspId != "code:them" {
		t.Errorf("directory not decoded: %+v", res.Data)
	}
	if res.Data.Total != 1 || res.Data.Page != 1 {
		t.Errorf("paging envelope not decoded: %+v", res.Data)
	}
}

// The query fields must reach the platform under the names it expects, since a
// silently dropped filter returns the whole directory instead of an error.
func TestClientV2VaspListSendsQueryFields(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)
	server, captured := newFakePlatform(t, merchantPublic, platformPrivate, emptyVaspPage())

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{
		VaspId: "code:them", Keyword: "Them", Page: 2, PageSize: MaxVaspPageSize,
	}); err != nil {
		t.Fatalf("TrVaspList: %v", err)
	}
	for _, want := range []string{`"vasp_id":"code:them"`, `"keyword":"Them"`, `"page":2`, `"page_size":200`} {
		if !strings.Contains(string(captured.body), want) {
			t.Errorf("request body missing %s: %s", want, captured.body)
		}
	}
}

// Omitting the key version header would make the canonical string diverge from
// the platform's, which defaults it to admin.
func TestClientV2AlwaysSendsKeyVersion(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)
	server, captured := newFakePlatform(t, merchantPublic, platformPrivate, emptyVaspPage())

	c, err := NewClientV2(ConfigV2{
		AppId: "testapp", BaseUrl: server.URL + "/shopapi/v2",
		PrivateKey: merchantPrivate, PlatformPublicKey: platformPublic,
	})
	if err != nil {
		t.Fatalf("NewClientV2: %v", err)
	}
	if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{}); err != nil {
		t.Fatalf("TrVaspList: %v", err)
	}
	if got := captured.headers.Get(HeaderKeyVersion); got != DefaultKeyVersion {
		t.Errorf("key version header = %q, want %q", got, DefaultKeyVersion)
	}
}

// The nonce must satisfy the platform's charset and length rule, and must not
// repeat across calls.
func TestClientV2NonceIsFreshAndValid(t *testing.T) {
	merchantPrivate, merchantPublic := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		nonce := r.Header.Get(HeaderNonce)
		if len(nonce) < 16 || len(nonce) > 64 {
			t.Errorf("nonce length %d outside 16..64: %q", len(nonce), nonce)
		}
		for _, ch := range nonce {
			isAllowed := ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || ch == '-'
			if !isAllowed {
				t.Errorf("nonce contains disallowed character %q: %s", ch, nonce)
				break
			}
		}
		if seen[nonce] {
			t.Errorf("nonce reused across requests: %s", nonce)
		}
		seen[nonce] = true
		_ = body
		respBody := []byte(`{"status":200,"msg":"ok","data":{"items":[],"page":1,"page_size":50,"total":0}}`)
		signResponse(t, w, platformPrivate, respBody)
	}))
	defer server.Close()
	_ = merchantPublic

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	for i := 0; i < 3; i++ {
		if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

// Status 618 is a normal intermediate state, so it must arrive as a typed error
// the caller can recognise rather than as an opaque failure.
//
// The body here is the exact shape the platform emits, "data":[] included. That
// empty array is the part that breaks a naive decode into a struct and takes the
// status down with it.
func TestClientV2SearchProcessingIsTypedError(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		signResponse(t, w, platformPrivate,
			[]byte(`{"status":618,"msg":"反查处理中","data":[],"date_time":"2026-07-29 12:00:00","time_stamp":1785297600}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrQueryTransfer(context.Background(), TrQueryTransferRequest{Coin: "usdt_trc20", Txid: "abc"})
	if err == nil {
		t.Fatal("expected an error for status 618")
	}
	if !IsSearchProcessing(err) {
		t.Errorf("IsSearchProcessing = false for status 618: %v", err)
	}
	if !IsRetryable(err) {
		t.Errorf("IsRetryable = false for status 618: %v", err)
	}
	if got := StatusCode(err); got != StatusSearchProcessing {
		t.Errorf("StatusCode = %d, want %d", got, StatusSearchProcessing)
	}
}

func TestClientV2BusinessErrorCarriesStatusAndMessage(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		signResponse(t, w, platformPrivate, []byte(`{"status":617,"msg":"codevasp: INVALID_TARGET_VASP_ID","data":[]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrVerifyAddress(context.Background(), TrVerifyAddressRequest{
		OriginatorVaspId: "code:me", Coin: "usdt_trc20", Address: "Tto",
	})
	if got := StatusCode(err); got != StatusProviderError {
		t.Fatalf("StatusCode = %d, want %d (err: %v)", got, StatusProviderError, err)
	}
	// The provider error type is the only thing that identifies the fault, so it
	// must not be flattened away.
	if !strings.Contains(err.Error(), "INVALID_TARGET_VASP_ID") {
		t.Errorf("provider error type lost: %v", err)
	}
	if IsRetryable(err) {
		t.Error("617 must not be reported as blanket retryable")
	}
}

// Early middleware rejections are answered before the merchant's key is known,
// so they carry no signature headers. The client must surface the business
// status rather than complaining about a missing signature.
func TestClientV2AcceptsUnsignedErrorResponse(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	_, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":602,"msg":"timestamp outside window","data":[]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrVaspList(context.Background(), TrVaspListRequest{})
	if got := StatusCode(err); got != StatusTimestampOutOfWindow {
		t.Errorf("StatusCode = %d, want %d (err: %v)", got, StatusTimestampOutOfWindow, err)
	}
}

// Every business status the platform can return must surface as a typed error
// with its status intact, not as a decode failure.
func TestClientV2AllBusinessStatusesSurface(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	statuses := []int{
		StatusTrNotEnabled, StatusVaspInvalid, StatusCoinNotMapped, StatusInvalidParameter,
		StatusProviderDown, StatusResourceNotFound, StatusSignatureCallback,
		StatusProviderError, StatusSearchProcessing, StatusVaspKeyCacheMissing,
	}
	for _, status := range statuses {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				signResponse(t, w, platformPrivate,
					[]byte(`{"status":`+strconv.Itoa(status)+`,"msg":"business error","data":[]}`))
			}))
			defer server.Close()

			c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
			_, err := c.TrTransfer(context.Background(), TrTransferRequest{Coin: "usdt_trc20"})
			if got := StatusCode(err); got != status {
				t.Errorf("StatusCode = %d, want %d (err: %v)", got, status, err)
			}
		})
	}
}

// A 200 with no data object would otherwise hand back a nil pointer that panics
// on first use, so it must be reported as an error instead.
func TestClientV2SuccessWithoutDataIsAnError(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	for _, body := range []string{
		`{"status":200,"msg":"ok"}`,
		`{"status":200,"msg":"ok","data":null}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			signResponse(t, w, platformPrivate, []byte(body))
		}))
		c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
		res, err := c.TrQueryTransfer(context.Background(), TrQueryTransferRequest{Coin: "c", Txid: "x"})
		if err == nil {
			t.Errorf("body %s returned no error while Data is nil", body)
		}
		if res.Data != nil {
			t.Errorf("body %s unexpectedly produced data", body)
		}
		server.Close()
	}
}

// A present but wrong signature must be rejected, or the check would be
// decorative.
func TestClientV2RejectsBadResponseSignature(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	otherPrivate, _ := rsaKeyPairPem(t, 2048)
	_, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		// Signed with a key the client does not trust.
		signResponse(t, w, otherPrivate, []byte(`{"status":200,"msg":"ok","data":[]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrVaspList(context.Background(), TrVaspListRequest{})
	if err == nil {
		t.Fatal("expected an error for a response signed by an untrusted key")
	}
	if !strings.Contains(err.Error(), "verify response signature") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A tampered body invalidates the signature even though the headers are intact.
func TestClientV2RejectsTamperedResponseBody(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		body := []byte(`{"status":200,"msg":"ok","data":[]}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "0123456789abcdef0123456789abcdef"
		canonical := crypto.BuildRespCanonical(timestamp, nonce, crypto.AlgRsaSha256, crypto.Sha256Hex(body))
		signature, err := crypto.SignV2(canonical, crypto.AlgRsaSha256, platformPrivate)
		if err != nil {
			t.Errorf("sign: %v", err)
			return
		}
		w.Header().Set(HeaderTimestamp, timestamp)
		w.Header().Set(HeaderNonce, nonce)
		w.Header().Set(HeaderSignAlg, crypto.AlgRsaSha256)
		w.Header().Set(HeaderSignature, signature)
		// Send something other than what was signed.
		_, _ = w.Write([]byte(`{"status":200,"msg":"ok","data":[{"vasp_id":"code:evil"}]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{}); err == nil {
		t.Fatal("expected an error for a body that does not match its signature")
	}
}

// A partial header set suggests tampering or truncation and must not be treated
// as "unsigned, therefore fine".
func TestClientV2RejectsIncompleteSignatureHeaders(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	_, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set(HeaderTimestamp, "1785297600")
		// Nonce, alg and signature deliberately absent.
		_, _ = w.Write([]byte(`{"status":200,"msg":"ok","data":[]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrVaspList(context.Background(), TrVaspListRequest{})
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("expected an incomplete headers error, got %v", err)
	}
}

// A validly signed but stale response must be rejected, so a captured response
// cannot be replayed indefinitely.
func TestClientV2RejectsStaleResponseTimestamp(t *testing.T) {
	merchantPrivate, _ := rsaKeyPairPem(t, 2048)
	platformPrivate, platformPublic := rsaKeyPairPem(t, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		body := []byte(`{"status":200,"msg":"ok","data":[]}`)
		// Correctly signed, but for a timestamp well outside the window.
		timestamp := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
		nonce := "0123456789abcdef0123456789abcdef"
		canonical := crypto.BuildRespCanonical(timestamp, nonce, crypto.AlgRsaSha256, crypto.Sha256Hex(body))
		signature, err := crypto.SignV2(canonical, crypto.AlgRsaSha256, platformPrivate)
		if err != nil {
			t.Errorf("sign: %v", err)
			return
		}
		w.Header().Set(HeaderTimestamp, timestamp)
		w.Header().Set(HeaderNonce, nonce)
		w.Header().Set(HeaderSignAlg, crypto.AlgRsaSha256)
		w.Header().Set(HeaderSignature, signature)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	c := newTestClient(t, server.URL+"/shopapi/v2", merchantPrivate, platformPublic)
	_, err := c.TrVaspList(context.Background(), TrVaspListRequest{})
	if err == nil || !strings.Contains(err.Error(), "timestamp outside") {
		t.Errorf("expected a stale timestamp error, got %v", err)
	}
}

func TestNewClientV2Validation(t *testing.T) {
	privatePem, publicPem := rsaKeyPairPem(t, 2048)
	weakPrivate, _ := rsaKeyPairPem(t, 1024)

	tests := []struct {
		name   string
		config ConfigV2
	}{
		{"missing app id", ConfigV2{BaseUrl: "http://x", PrivateKey: privatePem}},
		{"missing base url", ConfigV2{AppId: "a", PrivateKey: privatePem}},
		{"missing private key", ConfigV2{AppId: "a", BaseUrl: "http://x"}},
		{"malformed private key", ConfigV2{AppId: "a", BaseUrl: "http://x", PrivateKey: "nope"}},
		{"malformed platform public key", ConfigV2{AppId: "a", BaseUrl: "http://x", PrivateKey: privatePem, PlatformPublicKey: "nope"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewClientV2(test.config); err == nil {
				t.Error("expected a configuration error")
			}
		})
	}

	// A 1024 bit key parses, so it is only rejected when signing. Confirm the
	// failure is an error and not a panic.
	c, err := NewClientV2(ConfigV2{AppId: "a", BaseUrl: "http://127.0.0.1:1/shopapi/v2", PrivateKey: weakPrivate})
	if err != nil {
		t.Fatalf("NewClientV2 with a weak key: %v", err)
	}
	if _, err := c.TrVaspList(context.Background(), TrVaspListRequest{}); err == nil {
		t.Error("expected signing to reject a 1024 bit key")
	}

	if _, err := NewClientV2(ConfigV2{
		AppId: "a", BaseUrl: "http://x", PrivateKey: privatePem, PlatformPublicKey: publicPem,
	}); err != nil {
		t.Errorf("valid configuration rejected: %v", err)
	}
}

// The ciphertext and the key that produced it must be set together, since the
// platform forwards the key as the identifier the counterparty decrypts with.
func TestEncryptPayloadBindsCiphertextToPublicKey(t *testing.T) {
	senderSeed := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	receiverSeed := "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	receiverPub := "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="
	senderPub := "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

	encrypted, err := EncryptPayload(&travelrule.IVMS101{
		Beneficiary: &travelrule.Beneficiary{AccountNumber: []string{"Tto"}},
	}, senderSeed, receiverPub)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if encrypted.RemotePublicKey != receiverPub {
		t.Errorf("public key altered:\n got %q\nwant %q", encrypted.RemotePublicKey, receiverPub)
	}

	request := TrTransferRequest{Coin: "usdt_trc20"}
	encrypted.ApplyToTransfer(&request)
	if request.Payload != encrypted.Ciphertext || request.BeneficiaryPublicKey != receiverPub {
		t.Error("ApplyToTransfer must set both payload and public key")
	}

	// The counterparty must be able to decrypt using the announced key.
	decrypted, err := DecryptPayload(request.Payload, receiverSeed, senderPub)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if decrypted.Beneficiary == nil || len(decrypted.Beneficiary.AccountNumber) != 1 {
		t.Errorf("payload lost in round trip: %+v", decrypted)
	}
}

func TestEncryptPayloadRejectsBadKeys(t *testing.T) {
	if _, err := EncryptPayload(nil, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="); err == nil {
		t.Error("EncryptPayload accepted a nil payload")
	}
	payload := &travelrule.IVMS101{}
	if _, err := EncryptPayload(payload, "not base64!!!", "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="); err == nil {
		t.Error("EncryptPayload accepted a malformed private key")
	}
	if _, err := EncryptPayload(payload, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "short"); err == nil {
		t.Error("EncryptPayload accepted a malformed public key")
	}
}
