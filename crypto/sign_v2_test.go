package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// Golden fixture from the platform team's "Travel Rule 对接测试数据"
// (tr_callback_verify.json). It pins the four line response canonical string
// and an RSA-SHA256 signature over it.
const (
	fixtureCallbackTimestamp = "1785297600"
	fixtureCallbackNonce     = "0123456789abcdef0123456789abcdef"
	fixtureCallbackBody      = `{"vasp_id":"code:merchant","transfer_id":"fixture-transfer","status":"confirmed","txid":"fixture-txid"}`
	fixtureCallbackBodyHex   = "37be001608e4cca99aca138f7ae8f2928e3eca6e964cc1282ce53f6d27e1a70e"
	fixtureCallbackCanonical = "1785297600\n0123456789abcdef0123456789abcdef\nRSA-SHA256\n37be001608e4cca99aca138f7ae8f2928e3eca6e964cc1282ce53f6d27e1a70e"

	fixtureCallbackPubKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvVPnDgtf9FKg5qyUDLDa
+nzEwcBsUUMggV/KJxjKx930wNV86LB4SnnxhRbywqUcGDyfB5GM1tF9s43MamR1
RqnQh6ZVgnRWN8sLtVM60gNQOUXZtORcUuYBWhQvm/gUy5k+PJ2nLSoFjBeqqFXO
blpKXK+6/SQJe6wz1sWqawfph750GE9tjORZOyhBok/hT7VB96iw4JuLISOw+CGx
CQ3uUOs5Hlx40q7D4jAfCpfw94Dsy0ctUDVXRoxD1iinYTTb4sQXl6wyrpLRlFbt
59JUEVEeyyp4egDPJ/VHxTcA7gGkJ+K4l0jJzf7Q/uQ0fhXp95bQ3jzqkapxC/Wk
BwIDAQAB
-----END PUBLIC KEY-----
`
	fixtureCallbackSignature = "Ae5A4iwtqCZIKud7Zj4iK8sDDpacwYZMbWRaWc476a0Ma7bSRzKU2xlu2gKn1szOue5i+Vs/iKNig2MESu4PZYH5Vai8J/FnOfWusiUaXgvIVfq4z2CILcFUiHRziygFI0JfPnxZ2MvhsR+glKzv41F02E1Dfz41Xf7Bian2FAO5dG11s26MXmhd1YlW41529F/3n/HBcDR2wcQGEFvELEZ8SX3JGH5FZkSurEuEYip4O6MMPWDnFQcPFOnvCU+Qk9nXNy0fvVnl106FH8usCDsK99Db3GffvYsQp2fIm/spbNNB7HnjYeJfkS8AHoPqJICkr204Rk+s/gDK51sh3Q=="
)

// generateRsaPem returns a fresh key pair in the PEM forms the v2 API expects:
// PKCS#8 for the private key, PKIX for the public key.
func generateRsaPem(t *testing.T, bits int) (privatePem, publicPem string) {
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
	privatePem = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDer}))
	publicPem = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDer}))
	return privatePem, publicPem
}

func TestSha256HexEmptyBody(t *testing.T) {
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Sha256Hex(nil); got != want {
		t.Errorf("empty digest mismatch:\n got %q\nwant %q", got, want)
	}
	if got := Sha256Hex([]byte{}); got != want {
		t.Errorf("empty slice digest mismatch:\n got %q\nwant %q", got, want)
	}
}

// The request canonical string is exactly seven lines with no trailing
// newline. Assert it as one literal so an accidental extra separator fails
// loudly rather than only showing up as a signature mismatch in production.
func TestSignV2ParamsCanonicalGolden(t *testing.T) {
	params := SignV2Params{
		Method:        "POST",
		Path:          "/shopapi/v2/travel_rule/transfer",
		AppId:         "hxgmau9imt86qky9",
		KeyVersion:    "admin",
		Timestamp:     "1769500000",
		Nonce:         "7f3a9c2e1b5d4870",
		BodySha256Hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	const want = "POST\n" +
		"/shopapi/v2/travel_rule/transfer\n" +
		"hxgmau9imt86qky9\n" +
		"admin\n" +
		"1769500000\n" +
		"7f3a9c2e1b5d4870\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := params.Canonical()
	if got != want {
		t.Errorf("canonical mismatch:\n got %q\nwant %q", got, want)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("canonical must not end with a newline")
	}
	if lines := strings.Count(got, "\n") + 1; lines != 7 {
		t.Errorf("canonical must have 7 lines, got %d", lines)
	}
}

func TestBuildRespCanonicalMatchesFixture(t *testing.T) {
	got := BuildRespCanonical(fixtureCallbackTimestamp, fixtureCallbackNonce, AlgRsaSha256, Sha256Hex([]byte(fixtureCallbackBody)))
	if got != fixtureCallbackCanonical {
		t.Errorf("response canonical mismatch:\n got %q\nwant %q", got, fixtureCallbackCanonical)
	}
	if lines := strings.Count(got, "\n") + 1; lines != 4 {
		t.Errorf("response canonical must have 4 lines, got %d", lines)
	}
}

func TestFixtureBodyDigest(t *testing.T) {
	if got := Sha256Hex([]byte(fixtureCallbackBody)); got != fixtureCallbackBodyHex {
		t.Errorf("fixture body digest mismatch:\n got %q\nwant %q", got, fixtureCallbackBodyHex)
	}
}

// Proves the SDK verifies a signature the platform actually produced, not just
// one it produced itself.
func TestVerifyV2AcceptsPlatformFixture(t *testing.T) {
	err := VerifyV2(fixtureCallbackCanonical, AlgRsaSha256, fixtureCallbackPubKeyPem, fixtureCallbackSignature)
	if err != nil {
		t.Errorf("VerifyV2 rejected the platform fixture signature: %v", err)
	}
}

func TestVerifyV2RejectsTamperedFixtureCanonical(t *testing.T) {
	tampered := BuildRespCanonical(fixtureCallbackTimestamp, fixtureCallbackNonce, AlgRsaSha256, Sha256Hex([]byte(fixtureCallbackBody+" ")))
	if err := VerifyV2(tampered, AlgRsaSha256, fixtureCallbackPubKeyPem, fixtureCallbackSignature); err == nil {
		t.Error("VerifyV2 accepted a signature over a different body")
	}
}

func TestSignV2VerifyV2RoundTrip(t *testing.T) {
	privatePem, publicPem := generateRsaPem(t, 2048)
	canonical := SignV2Params{
		Method: "POST", Path: "/shopapi/v2/travel_rule/vaspList",
		AppId: "app", KeyVersion: "admin", Timestamp: "1769500000",
		Nonce: "0123456789abcdef", BodySha256Hex: Sha256Hex([]byte("{}")),
	}.Canonical()

	signature, err := SignV2(canonical, AlgRsaSha256, privatePem)
	if err != nil {
		t.Fatalf("SignV2: %v", err)
	}
	if err := VerifyV2(canonical, AlgRsaSha256, publicPem, signature); err != nil {
		t.Errorf("VerifyV2 on own signature: %v", err)
	}
}

// Each field of the canonical string must be covered by the signature. A field
// that is not would let an attacker vary it freely.
func TestVerifyV2RejectsEveryTamperedField(t *testing.T) {
	privatePem, publicPem := generateRsaPem(t, 2048)
	base := SignV2Params{
		Method: "POST", Path: "/shopapi/v2/travel_rule/transfer",
		AppId: "app", KeyVersion: "admin", Timestamp: "1769500000",
		Nonce: "0123456789abcdef", BodySha256Hex: Sha256Hex([]byte(`{"amount":"1.2"}`)),
	}
	signature, err := SignV2(base.Canonical(), AlgRsaSha256, privatePem)
	if err != nil {
		t.Fatalf("SignV2: %v", err)
	}

	tests := map[string]func(*SignV2Params){
		"method":      func(p *SignV2Params) { p.Method = "PUT" },
		"path":        func(p *SignV2Params) { p.Path = "/shopapi/v2/travel_rule/postTransfer" },
		"app_id":      func(p *SignV2Params) { p.AppId = "other" },
		"key_version": func(p *SignV2Params) { p.KeyVersion = "read" },
		"timestamp":   func(p *SignV2Params) { p.Timestamp = "1769500001" },
		"nonce":       func(p *SignV2Params) { p.Nonce = "fedcba9876543210" },
		"body":        func(p *SignV2Params) { p.BodySha256Hex = Sha256Hex([]byte(`{"amount":"9.9"}`)) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := base
			mutate(&tampered)
			if err := VerifyV2(tampered.Canonical(), AlgRsaSha256, publicPem, signature); err == nil {
				t.Errorf("VerifyV2 accepted a signature after tampering with %s", name)
			}
		})
	}
}

func TestSignV2RejectsUnsupportedAlgorithm(t *testing.T) {
	privatePem, publicPem := generateRsaPem(t, 2048)
	for _, alg := range []string{"", "MD5", "RSA-PSS-SHA256", "rsa-sha256", "none"} {
		if _, err := SignV2("canonical", alg, privatePem); err == nil {
			t.Errorf("SignV2 accepted algorithm %q", alg)
		}
		if err := VerifyV2("canonical", alg, publicPem, "c2ln"); err == nil {
			t.Errorf("VerifyV2 accepted algorithm %q", alg)
		}
	}
}

// The v2 entry point rejects keys weaker than 2048 bits. v1 has no such check,
// so this must be asserted rather than assumed.
func TestSignV2RejectsWeakKey(t *testing.T) {
	privatePem, publicPem := generateRsaPem(t, 1024)
	if _, err := SignV2("canonical", AlgRsaSha256, privatePem); err == nil {
		t.Error("SignV2 accepted a 1024 bit private key")
	}
	if err := VerifyV2("canonical", AlgRsaSha256, publicPem, "c2ln"); err == nil {
		t.Error("VerifyV2 accepted a 1024 bit public key")
	}
}

func TestSignV2RejectsMalformedKeys(t *testing.T) {
	if _, err := SignV2("canonical", AlgRsaSha256, "not a pem"); err == nil {
		t.Error("SignV2 accepted a non-PEM private key")
	}
	if err := VerifyV2("canonical", AlgRsaSha256, "not a pem", "c2ln"); err == nil {
		t.Error("VerifyV2 accepted a non-PEM public key")
	}
}

func TestVerifyV2RejectsMalformedSignature(t *testing.T) {
	_, publicPem := generateRsaPem(t, 2048)
	if err := VerifyV2("canonical", AlgRsaSha256, publicPem, "not base64!!!"); err == nil {
		t.Error("VerifyV2 accepted a non-base64 signature")
	}
}
