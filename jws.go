package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWSHeader represents the protected header of a JWS
type JWSHeader struct {
	Algorithm string `json:"alg"`
	JWK       *JWK   `json:"jwk,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Nonce     string `json:"nonce"`
	URL       string `json:"url"`
}

// JWSRequest represents a complete JWS request
type JWSRequest struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// VerifyJWSSignature verifies the signature of a JWS request using the provided JWK
func VerifyJWSSignature(jwsReq *JWSRequest, jwk *JWK) error {
	// Parse the protected header to get the algorithm
	protectedBytes, err := base64.RawURLEncoding.DecodeString(jwsReq.Protected)
	if err != nil {
		return fmt.Errorf("invalid protected header encoding: %v", err)
	}

	var header JWSHeader
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return fmt.Errorf("invalid protected header format: %v", err)
	}

	// Convert JWK to Go crypto public key
	publicKey, err := JWKToPublicKey(jwk)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to public key: %v", err)
	}

	// Create the signing input (protected + "." + payload)
	signingInput := jwsReq.Protected + "." + jwsReq.Payload

	// Decode the signature
	signature, err := base64.RawURLEncoding.DecodeString(jwsReq.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %v", err)
	}

	// Verify based on algorithm
	switch header.Algorithm {
	case "RS256":
		return verifyRS256(signingInput, signature, publicKey)
	case "ES256":
		return verifyES256(signingInput, signature, publicKey)
	case "EdDSA":
		return verifyEdDSA(signingInput, signature, publicKey)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", header.Algorithm)
	}
}

// verifyRS256 verifies an RS256 signature
func verifyRS256(signingInput string, signature []byte, publicKey interface{}) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected RSA public key for RS256, got %T", publicKey)
	}

	// Hash the signing input with SHA-256
	hash := sha256.Sum256([]byte(signingInput))

	// Verify the signature
	err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("RS256 signature verification failed: %v", err)
	}

	return nil
}

// verifyES256 verifies an ES256 signature
func verifyES256(signingInput string, signature []byte, publicKey interface{}) error {
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected ECDSA public key for ES256, got %T", publicKey)
	}

	// Hash the signing input with SHA-256
	hash := sha256.Sum256([]byte(signingInput))

	// ES256 signature is r || s, each 32 bytes for P-256
	if len(signature) != 64 {
		return fmt.Errorf("invalid ES256 signature length: expected 64 bytes, got %d", len(signature))
	}

	// Extract r and s from signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify the signature
	if !ecdsa.Verify(ecdsaKey, hash[:], r, s) {
		return fmt.Errorf("ES256 signature verification failed")
	}

	return nil
}

// verifyEdDSA verifies an EdDSA signature
func verifyEdDSA(signingInput string, signature []byte, publicKey interface{}) error {
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected Ed25519 public key for EdDSA, got %T", publicKey)
	}

	// Ed25519 doesn't require pre-hashing
	if !ed25519.Verify(ed25519Key, []byte(signingInput), signature) {
		return fmt.Errorf("EdDSA signature verification failed")
	}

	return nil
}

// ValidateJWSStructure validates the basic structure of a JWS request
func ValidateJWSStructure(jwsData map[string]interface{}) (*JWSRequest, error) {
	// Check required fields
	protected, ok := jwsData["protected"].(string)
	if !ok || protected == "" {
		return nil, fmt.Errorf("missing or invalid 'protected' field")
	}

	payload, ok := jwsData["payload"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'payload' field")
	}

	signature, ok := jwsData["signature"].(string)
	if !ok || signature == "" {
		return nil, fmt.Errorf("missing or invalid 'signature' field")
	}

	return &JWSRequest{
		Protected: protected,
		Payload:   payload,
		Signature: signature,
	}, nil
}

// ValidateProtectedHeader validates the protected header contains required fields
func ValidateProtectedHeader(protectedB64, expectedURL string) (*JWSHeader, error) {
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid protected header encoding: %v", err)
	}

	var header JWSHeader
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid protected header format: %v", err)
	}

	// Validate algorithm
	if header.Algorithm == "" {
		return nil, fmt.Errorf("missing 'alg' field in protected header")
	}

	// Validate nonce
	if header.Nonce == "" {
		return nil, fmt.Errorf("missing 'nonce' field in protected header")
	}

	// Validate URL
	if header.URL == "" {
		return nil, fmt.Errorf("missing 'url' field in protected header")
	}
	if header.URL != expectedURL {
		return nil, fmt.Errorf("URL mismatch: expected %s, got %s", expectedURL, header.URL)
	}

	// For new account, must have JWK (not kid)
	if header.JWK == nil {
		if header.KeyID != "" {
			return nil, fmt.Errorf("new account creation must use 'jwk' field, not 'kid'")
		}
		return nil, fmt.Errorf("missing 'jwk' field in protected header")
	}

	return &header, nil
}

// GetAlgorithmForJWK returns the expected algorithm for a given JWK
func GetAlgorithmForJWK(jwk *JWK) string {
	switch jwk.KeyType {
	case "RSA":
		return "RS256"
	case "EC":
		if jwk.Curve == "P-256" {
			return "ES256"
		}
	case "OKP":
		if jwk.Curve == "Ed25519" {
			return "EdDSA"
		}
	}
	return ""
}

// ValidateAlgorithmKeyMatch ensures the algorithm matches the key type
func ValidateAlgorithmKeyMatch(algorithm string, jwk *JWK) error {
	expectedAlg := GetAlgorithmForJWK(jwk)
	if expectedAlg == "" {
		return fmt.Errorf("unsupported key type/curve combination: %s/%s", jwk.KeyType, jwk.Curve)
	}
	
	if algorithm != expectedAlg {
		return fmt.Errorf("algorithm mismatch: key type %s expects %s, got %s", jwk.KeyType, expectedAlg, algorithm)
	}
	
	return nil
}