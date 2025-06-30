package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestVerifyJWSSignature_RSA(t *testing.T) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWK
	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	jwk := &JWK{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(nBytes),
		E:       base64.RawURLEncoding.EncodeToString(eBytes),
	}

	// Create test JWS
	header := map[string]interface{}{
		"alg":   "RS256",
		"nonce": "test-nonce",
		"url":   "https://example.com/acme/new-account",
		"jwk":   jwk,
	}
	headerBytes, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"contact":["mailto:test@example.com"]}`))

	// Sign the data
	signingInput := protected + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jwsReq := &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signatureB64,
	}

	// Test verification
	if err := VerifyJWSSignature(jwsReq, jwk); err != nil {
		t.Errorf("Valid RSA signature verification failed: %v", err)
	}
}

func TestVerifyJWSSignature_ECDSA(t *testing.T) {
	// Generate ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWK
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

	// Create test JWS
	header := map[string]interface{}{
		"alg":   "ES256",
		"nonce": "test-nonce",
		"url":   "https://example.com/acme/new-account",
		"jwk":   jwk,
	}
	headerBytes, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"contact":["mailto:test@example.com"]}`))

	// Sign the data
	signingInput := protected + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	// Convert r,s to fixed-length byte arrays (32 bytes each for P-256)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) < 32 {
		padding := make([]byte, 32-len(rBytes))
		rBytes = append(padding, rBytes...)
	}
	if len(sBytes) < 32 {
		padding := make([]byte, 32-len(sBytes))
		sBytes = append(padding, sBytes...)
	}

	signature := append(rBytes, sBytes...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jwsReq := &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signatureB64,
	}

	// Test verification
	if err := VerifyJWSSignature(jwsReq, jwk); err != nil {
		t.Errorf("Valid ECDSA signature verification failed: %v", err)
	}
}

func TestVerifyJWSSignature_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWK
	jwk := &JWK{
		KeyType: "OKP",
		Curve:   "Ed25519",
		X:       base64.RawURLEncoding.EncodeToString(pubKey),
	}

	// Create test JWS
	header := map[string]interface{}{
		"alg":   "EdDSA",
		"nonce": "test-nonce",
		"url":   "https://example.com/acme/new-account",
		"jwk":   jwk,
	}
	headerBytes, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"contact":["mailto:test@example.com"]}`))

	// Sign the data
	signingInput := protected + "." + payload
	signature := ed25519.Sign(privKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jwsReq := &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signatureB64,
	}

	// Test verification
	if err := VerifyJWSSignature(jwsReq, jwk); err != nil {
		t.Errorf("Valid Ed25519 signature verification failed: %v", err)
	}
}

func TestVerifyJWSSignature_InvalidSignature(t *testing.T) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create JWK
	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	jwk := &JWK{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(nBytes),
		E:       base64.RawURLEncoding.EncodeToString(eBytes),
	}

	// Create test JWS with invalid signature
	header := map[string]interface{}{
		"alg":   "RS256",
		"nonce": "test-nonce",
		"url":   "https://example.com/acme/new-account",
		"jwk":   jwk,
	}
	headerBytes, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"contact":["mailto:test@example.com"]}`))

	// Use invalid signature
	invalidSignature := make([]byte, 256)
	signatureB64 := base64.RawURLEncoding.EncodeToString(invalidSignature)

	jwsReq := &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signatureB64,
	}

	// Test verification should fail
	if err := VerifyJWSSignature(jwsReq, jwk); err == nil {
		t.Error("Invalid signature verification should have failed")
	}
}

func TestValidateJWSStructure(t *testing.T) {
	t.Run("valid structure", func(t *testing.T) {
		jwsData := map[string]interface{}{
			"protected": "eyJhbGciOiJSUzI1NiJ9",
			"payload":   "eyJjb250YWN0IjpbXX0",
			"signature": "abc123",
		}

		jwsReq, err := ValidateJWSStructure(jwsData)
		if err != nil {
			t.Errorf("Valid JWS structure validation failed: %v", err)
		}
		if jwsReq.Protected != "eyJhbGciOiJSUzI1NiJ9" {
			t.Error("Protected header not extracted correctly")
		}
	})

	t.Run("missing protected", func(t *testing.T) {
		jwsData := map[string]interface{}{
			"payload":   "eyJjb250YWN0IjpbXX0",
			"signature": "abc123",
		}

		_, err := ValidateJWSStructure(jwsData)
		if err == nil {
			t.Error("Should fail for missing protected header")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		jwsData := map[string]interface{}{
			"protected": "eyJhbGciOiJSUzI1NiJ9",
			"payload":   "eyJjb250YWN0IjpbXX0",
		}

		_, err := ValidateJWSStructure(jwsData)
		if err == nil {
			t.Error("Should fail for missing signature")
		}
	})
}

func TestValidateProtectedHeader(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "RSA",
			N:       "test-modulus",
			E:       "AQAB",
		}

		header := map[string]interface{}{
			"alg":   "RS256",
			"nonce": "test-nonce",
			"url":   "https://example.com/acme/new-account",
			"jwk":   jwk,
		}
		headerBytes, _ := json.Marshal(header)
		protected := base64.RawURLEncoding.EncodeToString(headerBytes)

		parsedHeader, err := ValidateProtectedHeader(protected, "https://example.com/acme/new-account")
		if err != nil {
			t.Errorf("Valid protected header validation failed: %v", err)
		}
		if parsedHeader.Algorithm != "RS256" {
			t.Error("Algorithm not extracted correctly")
		}
	})

	t.Run("URL mismatch", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "RSA",
			N:       "test-modulus",
			E:       "AQAB",
		}

		header := map[string]interface{}{
			"alg":   "RS256",
			"nonce": "test-nonce",
			"url":   "https://example.com/acme/wrong-url",
			"jwk":   jwk,
		}
		headerBytes, _ := json.Marshal(header)
		protected := base64.RawURLEncoding.EncodeToString(headerBytes)

		_, err := ValidateProtectedHeader(protected, "https://example.com/acme/new-account")
		if err == nil {
			t.Error("Should fail for URL mismatch")
		}
	})

	t.Run("missing nonce", func(t *testing.T) {
		jwk := &JWK{
			KeyType: "RSA",
			N:       "test-modulus",
			E:       "AQAB",
		}

		header := map[string]interface{}{
			"alg": "RS256",
			"url": "https://example.com/acme/new-account",
			"jwk": jwk,
		}
		headerBytes, _ := json.Marshal(header)
		protected := base64.RawURLEncoding.EncodeToString(headerBytes)

		_, err := ValidateProtectedHeader(protected, "https://example.com/acme/new-account")
		if err == nil {
			t.Error("Should fail for missing nonce")
		}
	})
}

func TestValidateAlgorithmKeyMatch(t *testing.T) {
	t.Run("RSA with RS256", func(t *testing.T) {
		jwk := &JWK{KeyType: "RSA"}
		err := ValidateAlgorithmKeyMatch("RS256", jwk)
		if err != nil {
			t.Errorf("RSA key should work with RS256: %v", err)
		}
	})

	t.Run("EC P-256 with ES256", func(t *testing.T) {
		jwk := &JWK{KeyType: "EC", Curve: "P-256"}
		err := ValidateAlgorithmKeyMatch("ES256", jwk)
		if err != nil {
			t.Errorf("EC P-256 key should work with ES256: %v", err)
		}
	})

	t.Run("Ed25519 with EdDSA", func(t *testing.T) {
		jwk := &JWK{KeyType: "OKP", Curve: "Ed25519"}
		err := ValidateAlgorithmKeyMatch("EdDSA", jwk)
		if err != nil {
			t.Errorf("Ed25519 key should work with EdDSA: %v", err)
		}
	})

	t.Run("RSA with wrong algorithm", func(t *testing.T) {
		jwk := &JWK{KeyType: "RSA"}
		err := ValidateAlgorithmKeyMatch("ES256", jwk)
		if err == nil {
			t.Error("RSA key should not work with ES256")
		}
	})
}

// Benchmark tests
func BenchmarkVerifyJWSSignature_RSA(b *testing.B) {
	// Setup
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	jwk := &JWK{
		KeyType: "RSA",
		N:       base64.RawURLEncoding.EncodeToString(nBytes),
		E:       base64.RawURLEncoding.EncodeToString(eBytes),
	}

	// Create signed JWS
	header := map[string]interface{}{
		"alg":   "RS256",
		"nonce": "test-nonce",
		"url":   "https://example.com/acme/new-account",
		"jwk":   jwk,
	}
	headerBytes, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"contact":[]}`))

	signingInput := protected + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jwsReq := &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signatureB64,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyJWSSignature(jwsReq, jwk)
	}
}