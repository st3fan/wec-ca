package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestValidateJWK(t *testing.T) {
	t.Run("valid RSA key", func(t *testing.T) {
		// Generate a test RSA key
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		nBytes := privKey.N.Bytes()
		eBytes := big.NewInt(int64(privKey.E)).Bytes()

		jwk := &JWK{
			KeyType: "RSA",
			N:       base64.RawURLEncoding.EncodeToString(nBytes),
			E:       base64.RawURLEncoding.EncodeToString(eBytes),
		}

		if err := ValidateJWK(jwk); err != nil {
			t.Errorf("ValidateJWK() failed for valid RSA key: %v", err)
		}
	})

	t.Run("valid ECDSA P-256 key", func(t *testing.T) {
		// Generate a test ECDSA key
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		xBytes := privKey.X.Bytes()
		yBytes := privKey.Y.Bytes()

		// Pad to 32 bytes for P-256
		if len(xBytes) < 32 {
			padding := make([]byte, 32-len(xBytes))
			xBytes = append(padding, xBytes...)
		}
		if len(yBytes) < 32 {
			padding := make([]byte, 32-len(yBytes))
			yBytes = append(padding, yBytes...)
		}

		jwk := &JWK{
			KeyType: "EC",
			Curve:   "P-256",
			X:       base64.RawURLEncoding.EncodeToString(xBytes),
			Y:       base64.RawURLEncoding.EncodeToString(yBytes),
		}

		if err := ValidateJWK(jwk); err != nil {
			t.Errorf("ValidateJWK() failed for valid ECDSA key: %v", err)
		}
	})

	t.Run("valid Ed25519 key", func(t *testing.T) {
		// Generate a test Ed25519 key
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		jwk := &JWK{
			KeyType: "OKP",
			Curve:   "Ed25519",
			X:       base64.RawURLEncoding.EncodeToString(pubKey),
		}

		if err := ValidateJWK(jwk); err != nil {
			t.Errorf("ValidateJWK() failed for valid Ed25519 key: %v", err)
		}
	})

	t.Run("missing key type", func(t *testing.T) {
		jwk := &JWK{}
		err := ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for missing key type")
		}
		if jwkErr, ok := err.(*JWKValidationError); ok {
			if jwkErr.Field != "kty" {
				t.Errorf("Expected field 'kty', got '%s'", jwkErr.Field)
			}
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		jwk := &JWK{KeyType: "unknown"}
		err := ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for unsupported key type")
		}
	})

	t.Run("RSA key too small", func(t *testing.T) {
		// Generate a small RSA key (1024 bits)
		privKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}

		nBytes := privKey.N.Bytes()
		eBytes := big.NewInt(int64(privKey.E)).Bytes()

		jwk := &JWK{
			KeyType: "RSA",
			N:       base64.RawURLEncoding.EncodeToString(nBytes),
			E:       base64.RawURLEncoding.EncodeToString(eBytes),
		}

		err = ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for small RSA key")
		}
	})

	t.Run("missing RSA modulus", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "RSA",
			E:       "AQAB",
		}
		err := ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for missing RSA modulus")
		}
	})

	t.Run("unsupported EC curve", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "EC",
			Curve:   "P-384",
			X:       "test",
			Y:       "test",
		}
		err := ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for unsupported curve")
		}
	})

	t.Run("invalid Ed25519 key length", func(t *testing.T) {
		// Wrong length key
		shortKey := make([]byte, 16) // Should be 32 bytes
		jwk := &JWK{
			KeyType: "OKP",
			Curve:   "Ed25519",
			X:       base64.RawURLEncoding.EncodeToString(shortKey),
		}
		err := ValidateJWK(jwk)
		if err == nil {
			t.Error("ValidateJWK() should fail for wrong Ed25519 key length")
		}
	})
}

func TestExtractJWKFromProtectedHeader(t *testing.T) {
	t.Run("valid JWK extraction", func(t *testing.T) {
		// Create a test JWK
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		nBytes := privKey.N.Bytes()
		eBytes := big.NewInt(int64(privKey.E)).Bytes()

		jwk := &JWK{
			KeyType: "RSA",
			N:       base64.RawURLEncoding.EncodeToString(nBytes),
			E:       base64.RawURLEncoding.EncodeToString(eBytes),
		}

		// Create protected header
		protected := map[string]interface{}{
			"alg":   "RS256",
			"nonce": "test-nonce",
			"url":   "https://example.com/acme/new-account",
			"jwk":   jwk,
		}

		protectedBytes, err := json.Marshal(protected)
		if err != nil {
			t.Fatal(err)
		}

		protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

		extractedJWK, err := ExtractJWKFromProtectedHeader(protectedB64)
		if err != nil {
			t.Errorf("ExtractJWKFromProtectedHeader() failed: %v", err)
		}

		if extractedJWK.KeyType != "RSA" {
			t.Errorf("Expected key type RSA, got %s", extractedJWK.KeyType)
		}
		if extractedJWK.N != jwk.N {
			t.Error("Extracted JWK modulus doesn't match")
		}
	})

	t.Run("missing JWK field", func(t *testing.T) {
		protected := map[string]interface{}{
			"alg":   "RS256",
			"nonce": "test-nonce",
			"url":   "https://example.com/acme/new-account",
		}

		protectedBytes, err := json.Marshal(protected)
		if err != nil {
			t.Fatal(err)
		}

		protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

		_, err = ExtractJWKFromProtectedHeader(protectedB64)
		if err == nil {
			t.Error("ExtractJWKFromProtectedHeader() should fail for missing JWK")
		}
	})

	t.Run("kid field present (should fail for new account)", func(t *testing.T) {
		protected := map[string]interface{}{
			"alg":   "RS256",
			"nonce": "test-nonce",
			"url":   "https://example.com/acme/new-account",
			"kid":   "existing-key-id",
		}

		protectedBytes, err := json.Marshal(protected)
		if err != nil {
			t.Fatal(err)
		}

		protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)

		_, err = ExtractJWKFromProtectedHeader(protectedB64)
		if err == nil {
			t.Error("ExtractJWKFromProtectedHeader() should fail when kid is used for new account")
		}
	})

	t.Run("invalid base64 encoding", func(t *testing.T) {
		_, err := ExtractJWKFromProtectedHeader("invalid-base64!")
		if err == nil {
			t.Error("ExtractJWKFromProtectedHeader() should fail for invalid base64")
		}
	})
}

func TestJWKToPublicKey(t *testing.T) {
	t.Run("RSA JWK to public key", func(t *testing.T) {
		// Generate test RSA key
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		nBytes := privKey.N.Bytes()
		eBytes := big.NewInt(int64(privKey.E)).Bytes()

		jwk := &JWK{
			KeyType: "RSA",
			N:       base64.RawURLEncoding.EncodeToString(nBytes),
			E:       base64.RawURLEncoding.EncodeToString(eBytes),
		}

		pubKey, err := JWKToPublicKey(jwk)
		if err != nil {
			t.Errorf("JWKToPublicKey() failed: %v", err)
		}

		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Error("Expected RSA public key")
		}

		if rsaPubKey.N.Cmp(privKey.N) != 0 {
			t.Error("Modulus doesn't match")
		}
		if rsaPubKey.E != privKey.E {
			t.Error("Exponent doesn't match")
		}
	})

	t.Run("ECDSA JWK to public key", func(t *testing.T) {
		// Generate test ECDSA key
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		xBytes := privKey.X.Bytes()
		yBytes := privKey.Y.Bytes()

		// Pad to 32 bytes for P-256
		if len(xBytes) < 32 {
			padding := make([]byte, 32-len(xBytes))
			xBytes = append(padding, xBytes...)
		}
		if len(yBytes) < 32 {
			padding := make([]byte, 32-len(yBytes))
			yBytes = append(padding, yBytes...)
		}

		jwk := &JWK{
			KeyType: "EC",
			Curve:   "P-256",
			X:       base64.RawURLEncoding.EncodeToString(xBytes),
			Y:       base64.RawURLEncoding.EncodeToString(yBytes),
		}

		pubKey, err := JWKToPublicKey(jwk)
		if err != nil {
			t.Errorf("JWKToPublicKey() failed: %v", err)
		}

		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Error("Expected ECDSA public key")
		}

		if ecdsaPubKey.X.Cmp(privKey.X) != 0 {
			t.Error("X coordinate doesn't match")
		}
		if ecdsaPubKey.Y.Cmp(privKey.Y) != 0 {
			t.Error("Y coordinate doesn't match")
		}
	})

	t.Run("Ed25519 JWK to public key", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		jwk := &JWK{
			KeyType: "OKP",
			Curve:   "Ed25519",
			X:       base64.RawURLEncoding.EncodeToString(pubKey),
		}

		extractedPubKey, err := JWKToPublicKey(jwk)
		if err != nil {
			t.Errorf("JWKToPublicKey() failed: %v", err)
		}

		ed25519PubKey, ok := extractedPubKey.(ed25519.PublicKey)
		if !ok {
			t.Error("Expected Ed25519 public key")
		}

		if !ed25519PubKey.Equal(pubKey) {
			t.Error("Ed25519 public keys don't match")
		}
	})
}

func TestSerializeDeserializeJWK(t *testing.T) {
	t.Run("RSA JWK serialization roundtrip", func(t *testing.T) {
		original := &JWK{
			KeyType: "RSA",
			N:       "test-modulus",
			E:       "AQAB",
		}

		serialized, err := SerializeJWK(original)
		if err != nil {
			t.Errorf("SerializeJWK() failed: %v", err)
		}

		deserialized, err := DeserializeJWK(serialized)
		if err != nil {
			t.Errorf("DeserializeJWK() failed: %v", err)
		}

		if deserialized.KeyType != original.KeyType {
			t.Error("Key type doesn't match after roundtrip")
		}
		if deserialized.N != original.N {
			t.Error("Modulus doesn't match after roundtrip")
		}
		if deserialized.E != original.E {
			t.Error("Exponent doesn't match after roundtrip")
		}
	})

	t.Run("invalid JSON deserialization", func(t *testing.T) {
		_, err := DeserializeJWK("invalid-json")
		if err == nil {
			t.Error("DeserializeJWK() should fail for invalid JSON")
		}
	})
}

func TestJWKValidationError(t *testing.T) {
	t.Run("error with field", func(t *testing.T) {
		err := &JWKValidationError{
			Message: "test message",
			Field:   "test_field",
		}

		expected := "JWK validation failed for field 'test_field': test message"
		if err.Error() != expected {
			t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("error without field", func(t *testing.T) {
		err := &JWKValidationError{
			Message: "test message",
		}

		expected := "JWK validation failed: test message"
		if err.Error() != expected {
			t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
		}
	})
}

// Benchmark tests for JWK operations
func BenchmarkValidateJWK_RSA(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()

	jwk := &JWK{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(nBytes),
		E:       base64.RawURLEncoding.EncodeToString(eBytes),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateJWK(jwk)
	}
}

func BenchmarkJWKToPublicKey_RSA(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()

	jwk := &JWK{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(nBytes),
		E:       base64.RawURLEncoding.EncodeToString(eBytes),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		JWKToPublicKey(jwk)
	}
}