package crypto

import (
	"encoding/base64"
	"testing"
)

// Cross-language fixtures published by the platform team as
// "Travel Rule 对接测试数据". Any divergence here means the SDK is not wire
// compatible with the platform, so these assert exact bytes.
const (
	fixtureSeedB64      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	fixturePubKeyB64    = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	fixtureMessageB64   = "Q29kZVZBU1AgY3Jvc3MtbGFuZ3VhZ2UgZml4dHVyZSBtZXNzYWdlAAE="
	fixtureSignatureB64 = "tlqmRs366BlEk8JSyz4mIQ9YXPYjSt1PNOxaVXV5HB2k8UUrKN9vDWpcUOjT2wM1Og701ATkeqTchGl1raxTDw=="

	fixtureReceiverSeedB64   = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	fixtureReceiverPubKeyB64 = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc="
	fixturePlaintext         = `{"ivms101":{"originatorPersons":[],"beneficiaryPersons":[]}}`
	fixtureCiphertextB64     = "qjBcBPP9Ddu+Vly8X2QTNBO1PHiW0OpFxMHjqtfNa4ByKJinR2n0Z1nmzgZd5e3v0J41ld2KXAyTMz0t2fgBu0bG3IcHQtnID1gg3P9OAA/q+2GAGUbEvm3B4ppXEtTOLRYWFg=="
)

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

func TestCodeVaspPublicKeyMatchesFixture(t *testing.T) {
	got, err := CodeVaspPublicKey(fixtureSeedB64)
	if err != nil {
		t.Fatalf("CodeVaspPublicKey: %v", err)
	}
	if got != fixturePubKeyB64 {
		t.Errorf("public key mismatch:\n got %q\nwant %q", got, fixturePubKeyB64)
	}
}

func TestSignCodeVaspMatchesFixture(t *testing.T) {
	message := mustDecodeB64(t, fixtureMessageB64)
	got, err := SignCodeVasp(message, fixtureSeedB64)
	if err != nil {
		t.Fatalf("SignCodeVasp: %v", err)
	}
	if got != fixtureSignatureB64 {
		t.Errorf("signature mismatch:\n got %q\nwant %q", got, fixtureSignatureB64)
	}
}

func TestVerifyCodeVaspAcceptsFixture(t *testing.T) {
	message := mustDecodeB64(t, fixtureMessageB64)
	if err := VerifyCodeVasp(message, fixtureSignatureB64, fixturePubKeyB64); err != nil {
		t.Errorf("VerifyCodeVasp on valid fixture: %v", err)
	}
}

func TestVerifyCodeVaspRejectsTamperedMessage(t *testing.T) {
	message := mustDecodeB64(t, fixtureMessageB64)
	message[0] ^= 0xff
	if err := VerifyCodeVasp(message, fixtureSignatureB64, fixturePubKeyB64); err == nil {
		t.Error("VerifyCodeVasp accepted a tampered message")
	}
}

// A 64 byte full key and the 32 byte seed it expands from must behave
// identically, since the CodeVASP dashboard issues seeds but merchants may
// store either form.
func TestSignCodeVaspAcceptsFullKeyAndSeed(t *testing.T) {
	seed := mustDecodeB64(t, fixtureSeedB64)
	fullKey := make([]byte, 0, 64)
	fullKey = append(fullKey, seed...)
	fullKey = append(fullKey, mustDecodeB64(t, fixturePubKeyB64)...)
	fullKeyB64 := base64.StdEncoding.EncodeToString(fullKey)

	message := mustDecodeB64(t, fixtureMessageB64)
	fromFull, err := SignCodeVasp(message, fullKeyB64)
	if err != nil {
		t.Fatalf("SignCodeVasp with 64 byte key: %v", err)
	}
	if fromFull != fixtureSignatureB64 {
		t.Errorf("64 byte key signature mismatch:\n got %q\nwant %q", fromFull, fixtureSignatureB64)
	}

	pub, err := CodeVaspPublicKey(fullKeyB64)
	if err != nil {
		t.Fatalf("CodeVaspPublicKey with 64 byte key: %v", err)
	}
	if pub != fixturePubKeyB64 {
		t.Errorf("64 byte key public key mismatch:\n got %q\nwant %q", pub, fixturePubKeyB64)
	}
}

func TestSignCodeVaspRejectsBadKeyLength(t *testing.T) {
	if _, err := SignCodeVasp([]byte("x"), base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("SignCodeVasp accepted a key of invalid length")
	}
}

// A 64 byte key carries its own public half, and nothing forces it to match the
// seed. Such a key still signs, but the signature verifies against neither
// candidate public key, so it has to be rejected up front rather than failing
// silently in production.
func TestSignCodeVaspRejectsInconsistentFullKey(t *testing.T) {
	seed := mustDecodeB64(t, fixtureSeedB64)
	wrongTail := mustDecodeB64(t, fixtureReceiverPubKeyB64) // a different key's public half

	inconsistent := make([]byte, 0, 64)
	inconsistent = append(inconsistent, seed...)
	inconsistent = append(inconsistent, wrongTail...)
	keyB64 := base64.StdEncoding.EncodeToString(inconsistent)

	if _, err := SignCodeVasp([]byte("message"), keyB64); err == nil {
		t.Error("SignCodeVasp accepted a key whose public half does not match its seed")
	}
	if _, err := CodeVaspPublicKey(keyB64); err == nil {
		t.Error("CodeVaspPublicKey accepted an inconsistent key")
	}
	if _, err := NewCipher(keyB64, fixtureReceiverPubKeyB64); err == nil {
		t.Error("NewCipher accepted an inconsistent key")
	}
}

// The receiver decrypts with its own private key plus the sender's public key.
func TestCipherDecryptMatchesFixture(t *testing.T) {
	cipher, err := NewCipher(fixtureReceiverSeedB64, fixturePubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	plain, err := cipher.Decrypt(mustDecodeB64(t, fixtureCiphertextB64))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != fixturePlaintext {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", plain, fixturePlaintext)
	}
}

func TestCipherRoundTrip(t *testing.T) {
	sender, err := NewCipher(fixtureSeedB64, fixtureReceiverPubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher sender: %v", err)
	}
	receiver, err := NewCipher(fixtureReceiverSeedB64, fixturePubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher receiver: %v", err)
	}

	sealed, err := sender.Encrypt([]byte(fixturePlaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(sealed) <= boxNonceSize {
		t.Fatalf("ciphertext too short: %d bytes", len(sealed))
	}
	plain, err := receiver.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != fixturePlaintext {
		t.Errorf("round trip mismatch:\n got %q\nwant %q", plain, fixturePlaintext)
	}
}

// The nonce is random per call, so identical plaintext must produce different
// ciphertext. This is why a ciphertext and the public key used to build it can
// never be sourced independently.
func TestCipherEncryptIsNonDeterministic(t *testing.T) {
	sender, err := NewCipher(fixtureSeedB64, fixtureReceiverPubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	first, err := sender.Encrypt([]byte(fixturePlaintext))
	if err != nil {
		t.Fatalf("Encrypt first: %v", err)
	}
	second, err := sender.Encrypt([]byte(fixturePlaintext))
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}
	if string(first) == string(second) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext")
	}
}

func TestCipherDecryptRejectsWrongKey(t *testing.T) {
	// Own key correct, remote key wrong: box.Open must fail.
	cipher, err := NewCipher(fixtureReceiverSeedB64, fixtureReceiverPubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if _, err := cipher.Decrypt(mustDecodeB64(t, fixtureCiphertextB64)); err == nil {
		t.Error("Decrypt succeeded with the wrong remote public key")
	}
}

func TestCipherDecryptRejectsShortCiphertext(t *testing.T) {
	cipher, err := NewCipher(fixtureReceiverSeedB64, fixturePubKeyB64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	if _, err := cipher.Decrypt(make([]byte, boxNonceSize-1)); err == nil {
		t.Error("Decrypt accepted a ciphertext shorter than the nonce")
	}
}

func TestDecodeEd25519PublicKeyRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	if _, err := DecodeEd25519PublicKey(short); err == nil {
		t.Error("DecodeEd25519PublicKey accepted a 31 byte key")
	}
	if _, err := DecodeEd25519PublicKey("not base64!!!"); err == nil {
		t.Error("DecodeEd25519PublicKey accepted invalid base64")
	}
}

// The CodeVASP string-to-sign is datetime, then body, then nonce as 4 bytes
// big endian.
func TestSigningMessageLayout(t *testing.T) {
	got := SigningMessage("2026-07-29T12:00:00+0000", []byte(`{"a":1}`), 0x01020304)
	want := append([]byte("2026-07-29T12:00:00+0000"), []byte(`{"a":1}`)...)
	want = append(want, 0x01, 0x02, 0x03, 0x04)
	if string(got) != string(want) {
		t.Errorf("signing message mismatch:\n got %q\nwant %q", got, want)
	}
}
