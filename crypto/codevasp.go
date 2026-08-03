// This file implements the CodeVASP (CODE Travel Rule network) primitives a
// merchant needs:
//
//   - Ed25519 signing, for the signature callback the platform calls before
//     every outbound CodeVASP request.
//   - NaCl box (X25519 + XSalsa20 + Poly1305) encryption of the IVMS101
//     payload, which the platform never decrypts.
//
// Both use the same Ed25519 key pair. Encryption additionally requires
// converting that key pair to Curve25519, which is done internally.
//
// The conversion is implemented with the standard library plus
// filippo.io/edwards25519 rather than the unmaintained github.com/agl/ed25519.
// Both produce byte-identical results, so this stays wire compatible with the
// platform side.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// boxNonceSize is the NaCl box nonce length. It is prefixed to the ciphertext.
const boxNonceSize = 24

// SignCodeVasp signs message with a base64 Ed25519 private key and returns the
// standard base64 signature.
//
// The key may be a 32 byte seed (what the CodeVASP dashboard issues) or a 64
// byte full key. message is signed as given: this function does not build the
// CodeVASP string-to-sign, generate a nonce, or add a datetime. The platform
// hands over the exact bytes to sign in the signature callback.
func SignCodeVasp(message []byte, base64PrivateKey string) (string, error) {
	privateKey, err := parseEd25519PrivateKey(base64PrivateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message)), nil
}

// VerifyCodeVasp verifies a base64 Ed25519 signature over message using a
// base64 Ed25519 public key.
func VerifyCodeVasp(message []byte, base64Signature, base64PublicKey string) error {
	publicKey, err := DecodeEd25519PublicKey(base64PublicKey)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return fmt.Errorf("decode signature base64 failed: %w", err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("ed25519 signature verify failed")
	}
	return nil
}

// CodeVaspPublicKey derives the base64 Ed25519 public key from a base64
// private key. Accepts a 32 byte seed or a 64 byte full key.
func CodeVaspPublicKey(base64PrivateKey string) (string, error) {
	privateKey, err := parseEd25519PrivateKey(base64PrivateKey)
	if err != nil {
		return "", err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// SigningMessage builds the CodeVASP string-to-sign: the datetime string, then
// the raw body bytes, then the nonce as 4 bytes big endian.
//
// A merchant does not normally need this: the platform sends the assembled
// bytes in the signature callback. It is exported so the construction can be
// asserted in tests and reused if a merchant ever drives CodeVASP directly.
func SigningMessage(datetime string, body []byte, nonce uint32) []byte {
	message := make([]byte, 0, len(datetime)+len(body)+4)
	message = append(message, datetime...)
	message = append(message, body...)
	var nonceBytes [4]byte
	binary.BigEndian.PutUint32(nonceBytes[:], nonce)
	return append(message, nonceBytes[:]...)
}

// Cipher holds a Curve25519 key pair converted from Ed25519 keys, ready for
// NaCl box sealing and opening. Build it with NewCipher.
type Cipher struct {
	privateKey *[32]byte
	publicKey  *[32]byte
}

// NewCipher pairs your own base64 Ed25519 private key with the counterparty's
// base64 Ed25519 public key and converts both to Curve25519.
//
// NaCl box is symmetric in its pairing: the same "own private key + remote
// public key" combination both encrypts and decrypts.
//
// The private key must be available in full. A sign-only HSM or KMS cannot
// back this: box needs the raw scalar, and that is not a signing operation.
func NewCipher(base64OwnPrivateKey, base64RemotePublicKey string) (*Cipher, error) {
	ownPrivate, err := parseEd25519PrivateKey(base64OwnPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("own private key: %w", err)
	}
	remotePublic, err := DecodeEd25519PublicKey(base64RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("remote public key: %w", err)
	}

	curvePrivate := ed25519PrivateToCurve25519(ownPrivate)
	curvePublic, err := ed25519PublicToCurve25519(remotePublic)
	if err != nil {
		return nil, err
	}
	return &Cipher{privateKey: curvePrivate, publicKey: curvePublic}, nil
}

// Encrypt seals msg and returns "24 byte random nonce || box ciphertext".
//
// The nonce is fresh on every call, so encrypting the same plaintext twice
// yields different bytes. That is why the ciphertext and the public key used
// to produce it must always travel together.
func (c *Cipher) Encrypt(msg []byte) ([]byte, error) {
	var nonce [boxNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate box nonce: %w", err)
	}
	return box.Seal(nonce[:], msg, &nonce, c.publicKey, c.privateKey), nil
}

// Decrypt opens a ciphertext produced by Encrypt, whose first 24 bytes are the
// nonce.
func (c *Cipher) Decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) < boxNonceSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, want at least %d", len(encrypted), boxNonceSize)
	}
	var nonce [boxNonceSize]byte
	copy(nonce[:], encrypted[:boxNonceSize])
	decrypted, ok := box.Open(nil, encrypted[boxNonceSize:], &nonce, c.publicKey, c.privateKey)
	if !ok {
		return nil, errors.New("decrypt payload failed: wrong key pair or corrupted ciphertext")
	}
	return decrypted, nil
}

// DecodeEd25519PublicKey decodes a base64 Ed25519 public key and checks its
// length.
//
// The encoding is case sensitive. Never normalise the case of a base64 public
// key: the platform matches it against its cached key set and forwards it
// verbatim to the counterparty as a key identifier.
func DecodeEd25519PublicKey(base64PublicKey string) (ed25519.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key base64 failed: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
	return keyBytes, nil
}

// parseEd25519PrivateKey accepts a base64 32 byte seed or 64 byte full key.
//
// For a 64 byte key the trailing public half is checked against the half derived
// from the seed. An Ed25519 private key carries its own public key, and nothing
// forces the two to agree: a mismatched key still signs, but the signature
// verifies against neither candidate public key. Rejecting it here turns a
// silent production failure into a startup error.
func parseEd25519PrivateKey(base64PrivateKey string) (ed25519.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key base64 failed: %w", err)
	}
	switch len(keyBytes) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(keyBytes), nil
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(keyBytes)
		derived := ed25519.NewKeyFromSeed(privateKey.Seed())
		if !derived.Equal(privateKey) {
			return nil, errors.New("invalid private key: the embedded public key does not match the seed")
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("invalid private key length: got %d, want %d or %d",
			len(keyBytes), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// ed25519PrivateToCurve25519 derives the Curve25519 scalar from an Ed25519
// private key: SHA-512 the seed, take the low 32 bytes, then clamp.
//
// This is the standard Ed25519 key expansion, so it matches every other
// implementation of the conversion.
func ed25519PrivateToCurve25519(privateKey ed25519.PrivateKey) *[32]byte {
	digest := sha512.Sum512(privateKey.Seed())
	var curvePrivate [32]byte
	copy(curvePrivate[:], digest[:32])
	curvePrivate[0] &= 248
	curvePrivate[31] &= 127
	curvePrivate[31] |= 64
	return &curvePrivate
}

// ed25519PublicToCurve25519 maps an Ed25519 public key from the Edwards curve
// to its birationally equivalent Montgomery form.
func ed25519PublicToCurve25519(publicKey ed25519.PublicKey) (*[32]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 public key to curve25519 failed: %w", err)
	}
	var curvePublic [32]byte
	copy(curvePublic[:], point.BytesMontgomery())
	return &curvePublic, nil
}
