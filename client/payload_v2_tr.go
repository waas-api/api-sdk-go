package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/waas-api/api-sdk-go/crypto"
	"github.com/waas-api/api-sdk-go/travelrule"
)

// EncryptedPayload is an encrypted IVMS101 payload together with the public key
// that encrypted it.
//
// The two are kept together because they cannot be sourced independently. The
// platform puts RemotePublicKey into the request's public-key field as a key
// identifier, telling the counterparty which of its keys to decrypt with. A
// NaCl box ciphertext is bound to a specific key pair, so if the merchant
// encrypted with key A while the header announced key B, the counterparty would
// try the wrong private key and decryption would fail. During a key rotation
// both keys are valid at once, which makes the mismatch easy to hit.
//
// Set both fields through ApplyToTransfer, ApplyToVerifyAddress or
// ApplyToPostTransfer rather than assigning them separately.
type EncryptedPayload struct {
	// Ciphertext is base64 of "24 byte nonce || box ciphertext".
	Ciphertext string
	// RemotePublicKey is the counterparty's base64 Ed25519 public key exactly
	// as it was used for encryption, case preserved.
	RemotePublicKey string
}

// EncryptPayload encrypts an IVMS101 payload for a counterparty.
//
// ownPrivateKey is the merchant's base64 Ed25519 private key, either a 32 byte
// seed or a 64 byte full key. remotePubKey is the counterparty's base64 public
// key taken from TrVaspList; pass it through unchanged, since its case is
// significant.
//
// This needs the private key itself, not a signing interface: NaCl box performs
// scalar multiplication with the raw key, which a sign-only HSM or KMS cannot
// do. If the private key must never leave a hardware boundary, encryption has
// to happen inside that boundary and only the resulting ciphertext passed in.
func EncryptPayload(payload *travelrule.IVMS101, ownPrivateKey, remotePubKey string) (EncryptedPayload, error) {
	if payload == nil {
		return EncryptedPayload{}, fmt.Errorf("payload required")
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("marshal ivms101: %w", err)
	}
	return EncryptPayloadBytes(plaintext, ownPrivateKey, remotePubKey)
}

// EncryptPayloadBytes encrypts an already serialized payload. Use it when the
// IVMS101 document is produced elsewhere and its exact bytes must be preserved.
func EncryptPayloadBytes(plaintext []byte, ownPrivateKey, remotePubKey string) (EncryptedPayload, error) {
	cipher, err := crypto.NewCipher(ownPrivateKey, remotePubKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	sealed, err := cipher.Encrypt(plaintext)
	if err != nil {
		return EncryptedPayload{}, err
	}
	return EncryptedPayload{
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		// Record the key as given, so what goes on the wire is what was used.
		RemotePublicKey: remotePubKey,
	}, nil
}

// ApplyToTransfer sets both Payload and BeneficiaryPublicKey on a transfer request.
func (p EncryptedPayload) ApplyToTransfer(request *TrTransferRequest) {
	request.Payload = p.Ciphertext
	request.BeneficiaryPublicKey = p.RemotePublicKey
}

// ApplyToVerifyAddress sets both Payload and BeneficiaryPublicKey on an address
// verification request, which switches it to the synchronous branch. That
// branch also requires BeneficiaryVaspId.
func (p EncryptedPayload) ApplyToVerifyAddress(request *TrVerifyAddressRequest) {
	request.Payload = p.Ciphertext
	request.BeneficiaryPublicKey = p.RemotePublicKey
}

// ApplyToPostTransfer sets both Payload and OriginatorPublicKey on a
// postTransfer request.
func (p EncryptedPayload) ApplyToPostTransfer(request *TrPostTransferRequest) {
	request.Payload = p.Ciphertext
	request.OriginatorPublicKey = p.RemotePublicKey
}

// DecryptPayload decrypts a base64 ciphertext received from a counterparty and
// unmarshals it into an IVMS101 document.
//
// ownPrivateKey is the merchant's base64 Ed25519 private key; remotePubKey is
// the counterparty's base64 public key. On an inbound callback, use the
// originator_public_key the platform supplies: that is the key it actually
// verified the request against, not the untrusted value from the request header.
func DecryptPayload(ciphertextBase64, ownPrivateKey, remotePubKey string) (*travelrule.IVMS101, error) {
	plaintext, err := DecryptPayloadBytes(ciphertextBase64, ownPrivateKey, remotePubKey)
	if err != nil {
		return nil, err
	}
	var payload travelrule.IVMS101
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal ivms101: %w", err)
	}
	return &payload, nil
}

// DecryptPayloadBytes decrypts a base64 ciphertext and returns the raw
// plaintext, for payloads that are not plain IVMS101 or whose exact bytes
// matter.
func DecryptPayloadBytes(ciphertextBase64, ownPrivateKey, remotePubKey string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("decode payload base64: %w", err)
	}
	cipher, err := crypto.NewCipher(ownPrivateKey, remotePubKey)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(sealed)
}
