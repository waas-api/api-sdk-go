package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/waas-api/api-sdk-go/crypto"
)

// v2 signature headers.
const (
	HeaderAppId      = "X-Cbc-App-Id"
	HeaderKeyVersion = "X-Cbc-Key-Version"
	HeaderTimestamp  = "X-Cbc-Timestamp"
	HeaderNonce      = "X-Cbc-Nonce"
	HeaderSignAlg    = "X-Cbc-Sign-Alg"
	HeaderSignature  = "X-Cbc-Signature"
)

// DefaultKeyVersion is the key version assumed when none is configured. The
// platform applies the same default before building the string-to-sign, so both
// sides must agree on it.
const DefaultKeyVersion = "admin"

// defaultTimeoutV2 leaves room for the platform's in-request VASP lookup, which
// spends up to 8 seconds polling before giving up and answering 618.
const defaultTimeoutV2 = 30 * time.Second

// maxResponseBytesV2 bounds the response size this client will process. The
// check happens after the body is read, so it guards against acting on an
// absurdly large response rather than against memory exhaustion.
const maxResponseBytesV2 = 1 << 20

// responseTimestampWindow is the accepted clock skew on a signed response. It is
// generous because a slow in-request VASP lookup can delay a response by several
// seconds, and only bounds how long a captured response stays replayable.
const responseTimestampWindow = 5 * time.Minute

// ClientV2 is the Travel Rule client. It speaks the v2 signature scheme, where
// the signature travels in headers and the request body is signed as sent.
//
// This is separate from Client on purpose. The v1 client rewrites the body to
// insert a sign field, which is exactly what v2 forbids: the body must be
// signed and sent as the same bytes.
type ClientV2 interface {
	// TrVaspList fetches the VASP directory with each entry's public keys. This
	// is the starting point: use it to pick a counterparty and to obtain the
	// key that encrypts the payload. Cache the result and refresh periodically.
	TrVaspList(ctx context.Context, request TrVaspListRequest) (TrVaspListResponse, error)

	// TrVerifyAddress verifies an address against a known VASP, or looks up
	// which VASP owns it. The lookup branch usually answers 618 on the first
	// call; see IsSearchProcessing.
	TrVerifyAddress(ctx context.Context, request TrVerifyAddressRequest) (TrVerifyAddressResponse, error)

	// TrTransfer submits a withdrawal for Travel Rule handling. Check
	// RouteDecision on the result: only TR_CODE means an authorisation went out.
	TrTransfer(ctx context.Context, request TrTransferRequest) (TrTransferResponse, error)

	// TrQueryTransfer looks up the originating VASP of a settled deposit by
	// txid. Usually answers 618 on the first call. Keep the returned RequestId:
	// TrPostTransfer requires it.
	TrQueryTransfer(ctx context.Context, request TrQueryTransferRequest) (TrQueryTransferResponse, error)

	// TrPostTransfer supplies Travel Rule data for a deposit that settled
	// without an incoming authorisation.
	TrPostTransfer(ctx context.Context, request TrPostTransferRequest) (TrPostTransferResponse, error)
}

// ConfigV2 configures a Travel Rule client.
type ConfigV2 struct {
	// AppId is the merchant app id, required.
	AppId string `json:"app_id" yaml:"app_id"`
	// KeyVersion selects which registered public key verifies the request.
	// Defaults to DefaultKeyVersion when empty.
	KeyVersion string `json:"key_version" yaml:"key_version"`
	// BaseUrl is the v2 prefix, for example https://api.example.com/shopapi/v2
	// Required.
	BaseUrl string `json:"base_url" yaml:"base_url"`
	// PrivateKey is the merchant RSA private key that signs requests: PEM
	// PKCS#8, at least 2048 bits. This is the same key used for v1; there is no
	// need to issue a new one.
	PrivateKey string `json:"private_key" yaml:"private_key"`
	// PlatformPublicKey verifies response signatures: PEM PKIX. Optional. When
	// empty, response signatures are not checked, which is only appropriate for
	// local testing.
	PlatformPublicKey string `json:"platform_public_key" yaml:"platform_public_key"`
	// Timeout bounds a single request. Defaults to defaultTimeoutV2.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
}

// NewClientV2 builds a Travel Rule client. It returns an error rather than
// panicking, so a bad configuration surfaces at startup.
func NewClientV2(config ConfigV2) (ClientV2, error) {
	if config.AppId == "" {
		return nil, errors.New("app_id required")
	}
	if config.BaseUrl == "" {
		return nil, errors.New("base_url required")
	}
	if config.PrivateKey == "" {
		return nil, errors.New("private_key required")
	}
	// Fail here rather than on the first request: a weak or malformed key can
	// never produce an acceptable signature.
	if _, err := crypto.ParseRsaPrivateKey(config.PrivateKey); err != nil {
		return nil, fmt.Errorf("private_key invalid: %w", err)
	}
	if config.PlatformPublicKey != "" {
		if _, err := crypto.ParseRsaPublicKey(config.PlatformPublicKey); err != nil {
			return nil, fmt.Errorf("platform_public_key invalid: %w", err)
		}
	}
	if config.KeyVersion == "" {
		config.KeyVersion = DefaultKeyVersion
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultTimeoutV2
	}

	return &clientV2{
		conf: config,
		http: req.C().SetTimeout(config.Timeout),
	}, nil
}

type clientV2 struct {
	conf ConfigV2
	http *req.Client
}

func (c *clientV2) TrVaspList(ctx context.Context, request TrVaspListRequest) (res TrVaspListResponse, err error) {
	err = c.call(ctx, pathTrVaspList, request, &res, &res.ResponseV2)
	return res, err
}

func (c *clientV2) TrVerifyAddress(ctx context.Context, request TrVerifyAddressRequest) (res TrVerifyAddressResponse, err error) {
	err = c.call(ctx, pathTrVerifyAddress, request, &res, &res.ResponseV2)
	return res, err
}

func (c *clientV2) TrTransfer(ctx context.Context, request TrTransferRequest) (res TrTransferResponse, err error) {
	err = c.call(ctx, pathTrTransfer, request, &res, &res.ResponseV2)
	return res, err
}

func (c *clientV2) TrQueryTransfer(ctx context.Context, request TrQueryTransferRequest) (res TrQueryTransferResponse, err error) {
	err = c.call(ctx, pathTrQueryTransfer, request, &res, &res.ResponseV2)
	return res, err
}

func (c *clientV2) TrPostTransfer(ctx context.Context, request TrPostTransferRequest) (res TrPostTransferResponse, err error) {
	err = c.call(ctx, pathTrPostTransfer, request, &res, &res.ResponseV2)
	return res, err
}

// call performs one signed round trip.
//
// The body is marshalled exactly once. Those same bytes are hashed for the
// signature and handed to the transport, so a mismatch between what was signed
// and what was sent is structurally impossible. Never re-serialize after
// signing.
func (c *clientV2) call(ctx context.Context, p path, request, out any, envelope *ResponseV2) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	fullUrl := p.Build(c.conf.BaseUrl)
	// Derive the signed path from the URL that will actually be requested, so
	// the two cannot drift.
	parsed, err := url.Parse(fullUrl)
	if err != nil {
		return fmt.Errorf("parse url %q: %w", fullUrl, err)
	}

	nonce, err := newNonceV2()
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	canonical := crypto.SignV2Params{
		Method:        "POST",
		Path:          parsed.EscapedPath(),
		AppId:         c.conf.AppId,
		KeyVersion:    c.conf.KeyVersion,
		Timestamp:     timestamp,
		Nonce:         nonce,
		BodySha256Hex: crypto.Sha256Hex(body),
	}.Canonical()

	signature, err := crypto.SignV2(canonical, crypto.AlgRsaSha256, c.conf.PrivateKey)
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	resp, err := c.http.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader(HeaderAppId, c.conf.AppId).
		SetHeader(HeaderKeyVersion, c.conf.KeyVersion).
		SetHeader(HeaderTimestamp, timestamp).
		SetHeader(HeaderNonce, nonce).
		SetHeader(HeaderSignAlg, crypto.AlgRsaSha256).
		SetHeader(HeaderSignature, signature).
		SetBodyBytes(body).
		Post(fullUrl)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	respBody, err := resp.ToBytes()
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(respBody) > maxResponseBytesV2 {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytesV2)
	}

	// Verify before decoding, so nothing from an unverified body is acted upon.
	if err := c.verifyResponse(resp, respBody); err != nil {
		return err
	}

	if !resp.IsSuccessState() {
		return fmt.Errorf("bad http status %s: %s", resp.Status, truncate(respBody, 512))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	// Report the business status before anything else: on a non-200 the data
	// object is absent, so callers must get the status rather than a nil result.
	if envelope.Status != StatusOk {
		return &ApiErrorV2{Status: envelope.Status, Msg: envelope.Msg}
	}
	// A success with no data object would otherwise hand back a nil pointer that
	// panics on first use. Every response type implements dataCarrier, asserted
	// at compile time, so a missing implementation cannot slip through here.
	if carrier, ok := out.(dataCarrier); ok && !carrier.hasData() {
		return fmt.Errorf("response reported status %d but carried no data", envelope.Status)
	}
	return nil
}

// verifyResponse checks the response signature when one is present.
//
// The rule is "if signature headers are present they must verify", not
// "signatures must always be present". Errors rejected early by the platform's
// middleware, such as a bad signature or an expired timestamp, are answered
// before the merchant's identity and key are established, so those responses
// carry no signature. Demanding one unconditionally would mask the real cause.
func (c *clientV2) verifyResponse(resp *req.Response, body []byte) error {
	if c.conf.PlatformPublicKey == "" {
		return nil
	}
	timestamp := strings.TrimSpace(resp.Header.Get(HeaderTimestamp))
	nonce := strings.TrimSpace(resp.Header.Get(HeaderNonce))
	algorithm := strings.TrimSpace(resp.Header.Get(HeaderSignAlg))
	signature := strings.TrimSpace(resp.Header.Get(HeaderSignature))

	if timestamp == "" && nonce == "" && algorithm == "" && signature == "" {
		return nil
	}
	// A partial set means something tampered with or truncated the headers;
	// treat it as a failure rather than skipping the check.
	if timestamp == "" || nonce == "" || algorithm == "" || signature == "" {
		return errors.New("response signature headers incomplete")
	}

	canonical := crypto.BuildRespCanonical(timestamp, nonce, algorithm, crypto.Sha256Hex(body))
	if err := crypto.VerifyV2(canonical, algorithm, c.conf.PlatformPublicKey, signature); err != nil {
		return fmt.Errorf("verify response signature: %w", err)
	}

	// Reject a response whose timestamp is far from now, so a captured response
	// cannot be replayed indefinitely by something sitting in the path. Checked
	// after the signature, since an unverified timestamp is not worth acting on.
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("response timestamp malformed: %w", err)
	}
	skew := time.Since(time.Unix(seconds, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > responseTimestampWindow {
		return fmt.Errorf("response timestamp outside the %s window", responseTimestampWindow)
	}
	return nil
}

// newNonceV2 returns a 32 character hex nonce, within the 16 to 64 character
// [0-9a-zA-Z_-] range the platform accepts.
func newNonceV2() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func truncate(body []byte, limit int) string {
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "..."
}
