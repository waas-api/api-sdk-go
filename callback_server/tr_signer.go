package callback_server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/waas-api/api-sdk-go/crypto"
	"github.com/waas-api/api-sdk-go/travelrule"
)

// memorySigner holds an Ed25519 private key in process memory.
type memorySigner struct {
	privateKeyBase64 string
}

// NewMemorySigner builds a Signer from a base64 Ed25519 private key, either a
// 32 byte seed (what the CodeVASP dashboard issues) or a 64 byte full key.
//
// This keeps the key in process memory. It suits tests and self managed key
// storage, but the integration guidance requires production keys to live in an
// approved HSM, KMS or key management system: implement Signer against that
// instead. The platform neither receives nor stores this key.
func NewMemorySigner(privateKeyBase64 string) (Signer, error) {
	if privateKeyBase64 == "" {
		return nil, errors.New("private key required")
	}
	// Derive the public key now so a malformed key fails at construction rather
	// than on the first live callback.
	if _, err := crypto.CodeVaspPublicKey(privateKeyBase64); err != nil {
		return nil, fmt.Errorf("private key invalid: %w", err)
	}
	return &memorySigner{privateKeyBase64: privateKeyBase64}, nil
}

// Sign implements Signer.
func (s *memorySigner) Sign(message []byte) (string, error) {
	return crypto.SignCodeVasp(message, s.privateKeyBase64)
}

// PublicKey returns the base64 Ed25519 public key for a base64 private key.
//
// Use it to confirm the configured key matches the one registered with the
// platform. A mismatch is otherwise only discovered when the counterparty
// rejects a signature.
func PublicKey(privateKeyBase64 string) (string, error) {
	return crypto.CodeVaspPublicKey(privateKeyBase64)
}

// DecryptCallbackPayload decrypts an inbound callback payload.
//
// remotePubKeyBase64 must be the key the platform supplied on the callback:
// originator_public_key on verifyAddress and transfer, beneficiary_public_key on
// postTransfer. That value is the key the platform actually verified the inbound
// request against, taken from its local cache. Never use the public key from a
// raw inbound header: that is attacker supplied and verifying a signature with
// it proves nothing.
//
// ownPrivateKeyBase64 must be the private key itself. A sign-only HSM cannot do
// this, because NaCl box needs the raw key rather than a signing operation.
func DecryptCallbackPayload(payloadBase64, ownPrivateKeyBase64, remotePubKeyBase64 string) (*travelrule.IVMS101, error) {
	plaintext, err := DecryptCallbackPayloadBytes(payloadBase64, ownPrivateKeyBase64, remotePubKeyBase64)
	if err != nil {
		return nil, err
	}
	var payload travelrule.IVMS101
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal ivms101: %w", err)
	}
	return &payload, nil
}

// DecryptCallbackPayloadBytes decrypts an inbound payload and returns the raw
// plaintext, for payloads that are not plain IVMS101.
func DecryptCallbackPayloadBytes(payloadBase64, ownPrivateKeyBase64, remotePubKeyBase64 string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("decode payload base64: %w", err)
	}
	cipher, err := crypto.NewCipher(ownPrivateKeyBase64, remotePubKeyBase64)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(sealed)
}

// EncryptCallbackPayload encrypts the merchant's own IVMS101 for the reply to a
// callback.
//
// remotePubKeyBase64 must again be the verified key from the callback, so the
// counterparty can decrypt with the matching private key.
func EncryptCallbackPayload(payload *travelrule.IVMS101, ownPrivateKeyBase64, remotePubKeyBase64 string) (string, error) {
	if payload == nil {
		return "", errors.New("payload required")
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal ivms101: %w", err)
	}
	return EncryptCallbackPayloadBytes(plaintext, ownPrivateKeyBase64, remotePubKeyBase64)
}

// EncryptCallbackPayloadBytes encrypts already serialized plaintext for a
// callback reply.
func EncryptCallbackPayloadBytes(plaintext []byte, ownPrivateKeyBase64, remotePubKeyBase64 string) (string, error) {
	cipher, err := crypto.NewCipher(ownPrivateKeyBase64, remotePubKeyBase64)
	if err != nil {
		return "", err
	}
	sealed, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
