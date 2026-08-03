package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// AlgRsaSha256 is the only signature algorithm accepted by the v2 API.
// It means RSA PKCS#1 v1.5 padding over a SHA-256 digest.
const AlgRsaSha256 = "RSA-SHA256"

// minRsaKeyBits is the minimum modulus size accepted on the v2 API.
// v1 has no such check; do not relax this one.
const minRsaKeyBits = 2048

// SignV2Params holds the seven components of a v2 request string-to-sign.
//
// Every field must match the value actually put on the wire, byte for byte.
// In particular:
//
//   - Path is the URL escaped path only: no scheme, no host, no query string,
//     and no normalisation. The platform verifies against
//     url.URL.EscapedPath() of the incoming request.
//   - KeyVersion is "admin" when the X-Cbc-Key-Version header is not sent.
//     The platform applies that same default before building the canonical
//     string, so an empty value here would not match.
//   - BodySha256Hex is the lowercase hex SHA-256 of the raw request body
//     bytes. Sign the bytes you send; never re-serialize after signing.
type SignV2Params struct {
	Method        string
	Path          string
	AppId         string
	KeyVersion    string
	Timestamp     string
	Nonce         string
	BodySha256Hex string
}

// Canonical renders the request string-to-sign: seven lines joined by "\n",
// with no trailing newline.
func (p SignV2Params) Canonical() string {
	return strings.Join([]string{
		p.Method,
		p.Path,
		p.AppId,
		p.KeyVersion,
		p.Timestamp,
		p.Nonce,
		p.BodySha256Hex,
	}, "\n")
}

// BuildRespCanonical renders the four line string-to-sign used by both the
// synchronous v2 response and the asynchronous v2 callback: timestamp, nonce,
// algorithm, body digest. The request path is not part of it.
func BuildRespCanonical(timestamp, nonce, algorithm, bodySha256Hex string) string {
	return strings.Join([]string{timestamp, nonce, algorithm, bodySha256Hex}, "\n")
}

// Sha256Hex returns the lowercase hex SHA-256 of data.
// An empty input yields e3b0c442...b855.
func Sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// SignV2 signs a canonical string with an RSA private key in PEM PKCS#8 form
// and returns the standard base64 signature.
func SignV2(canonical, algorithm, privateKeyPem string) (string, error) {
	if algorithm != AlgRsaSha256 {
		return "", fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
	privateKey, err := ParseRsaPrivateKey(privateKeyPem)
	if err != nil {
		return "", err
	}
	if privateKey.N.BitLen() < minRsaKeyBits {
		return "", fmt.Errorf("RSA private key must be at least %d bits", minRsaKeyBits)
	}
	digest := sha256.Sum256([]byte(canonical))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("RSA-SHA256 sign failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyV2 verifies a base64 signature over a canonical string using an RSA
// public key in PEM PKIX form. It returns nil only when the signature is valid.
func VerifyV2(canonical, algorithm, publicKeyPem, signatureBase64 string) error {
	if algorithm != AlgRsaSha256 {
		return fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
	publicKey, err := ParseRsaPublicKey(publicKeyPem)
	if err != nil {
		return err
	}
	if publicKey.N.BitLen() < minRsaKeyBits {
		return fmt.Errorf("RSA public key must be at least %d bits", minRsaKeyBits)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("decode signature base64 failed: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return fmt.Errorf("RSA-SHA256 verify failed: %w", err)
	}
	return nil
}

// ParseRsaPrivateKey decodes a PEM PKCS#8 RSA private key.
func ParseRsaPrivateKey(privateKeyPem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("invalid RSA private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key failed: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

// ParseRsaPublicKey decodes a PEM PKIX RSA public key.
func ParseRsaPublicKey(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("invalid RSA public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key failed: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaKey, nil
}
