package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key as defined in RFC 7517
type JWK struct {
	KeyType   string `json:"kty"`           // Key Type (RSA, EC, OKP)
	Algorithm string `json:"alg,omitempty"` // Algorithm (RS256, ES256, EdDSA)
	Use       string `json:"use,omitempty"` // Public Key Use
	KeyID     string `json:"kid,omitempty"` // Key ID

	// RSA key parameters (kty: RSA)
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC key parameters (kty: EC)
	Curve string `json:"crv,omitempty"` // Curve
	X     string `json:"x,omitempty"`   // X coordinate
	Y     string `json:"y,omitempty"`   // Y coordinate

	// Note: OKP keys also use the "x" field, which maps to the same X field above
}

// JWKValidationError represents an error in JWK validation
type JWKValidationError struct {
	Message string
	Field   string
}

func (e *JWKValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("JWK validation failed for field '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("JWK validation failed: %s", e.Message)
}

// ValidateJWK validates a JWK according to ACME requirements
func ValidateJWK(jwk *JWK) error {
	if jwk.KeyType == "" {
		return &JWKValidationError{Message: "missing required field", Field: "kty"}
	}

	switch jwk.KeyType {
	case "RSA":
		return validateRSAKey(jwk)
	case "EC":
		return validateECKey(jwk)
	case "OKP":
		return validateOKPKey(jwk)
	default:
		return &JWKValidationError{
			Message: fmt.Sprintf("unsupported key type '%s' (supported: RSA, EC, OKP)", jwk.KeyType),
			Field:   "kty",
		}
	}
}

// validateRSAKey validates RSA JWK parameters
func validateRSAKey(jwk *JWK) error {
	if jwk.N == "" {
		return &JWKValidationError{Message: "missing required field for RSA key", Field: "n"}
	}
	if jwk.E == "" {
		return &JWKValidationError{Message: "missing required field for RSA key", Field: "e"}
	}

	// Decode and validate modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return &JWKValidationError{Message: "invalid base64url encoding", Field: "n"}
	}

	// Check minimum key size (2048 bits = 256 bytes)
	if len(nBytes) < 256 {
		return &JWKValidationError{
			Message: fmt.Sprintf("RSA key too small: %d bits (minimum 2048 bits required)", len(nBytes)*8),
			Field:   "n",
		}
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return &JWKValidationError{Message: "invalid base64url encoding", Field: "e"}
	}

	// Common exponents: 3, 65537 (0x010001)
	e := new(big.Int).SetBytes(eBytes)
	if e.Cmp(big.NewInt(3)) < 0 {
		return &JWKValidationError{Message: "RSA exponent too small", Field: "e"}
	}

	return nil
}

// validateECKey validates Elliptic Curve JWK parameters
func validateECKey(jwk *JWK) error {
	if jwk.Curve == "" {
		return &JWKValidationError{Message: "missing required field for EC key", Field: "crv"}
	}
	if jwk.X == "" {
		return &JWKValidationError{Message: "missing required field for EC key", Field: "x"}
	}
	if jwk.Y == "" {
		return &JWKValidationError{Message: "missing required field for EC key", Field: "y"}
	}

	// Only support P-256 for ACME (ES256)
	if jwk.Curve != "P-256" {
		return &JWKValidationError{
			Message: fmt.Sprintf("unsupported curve '%s' (supported: P-256)", jwk.Curve),
			Field:   "crv",
		}
	}

	// Validate coordinate encoding
	if _, err := base64.RawURLEncoding.DecodeString(jwk.X); err != nil {
		return &JWKValidationError{Message: "invalid base64url encoding", Field: "x"}
	}
	if _, err := base64.RawURLEncoding.DecodeString(jwk.Y); err != nil {
		return &JWKValidationError{Message: "invalid base64url encoding", Field: "y"}
	}

	return nil
}

// validateOKPKey validates Octet Key Pair (EdDSA) JWK parameters
func validateOKPKey(jwk *JWK) error {
	if jwk.Curve == "" {
		return &JWKValidationError{Message: "missing required field for OKP key", Field: "crv"}
	}
	if jwk.X == "" {
		return &JWKValidationError{Message: "missing required field for OKP key", Field: "x"}
	}

	// Only support Ed25519
	if jwk.Curve != "Ed25519" {
		return &JWKValidationError{
			Message: fmt.Sprintf("unsupported curve '%s' (supported: Ed25519)", jwk.Curve),
			Field:   "crv",
		}
	}

	// Validate X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return &JWKValidationError{Message: "invalid base64url encoding", Field: "x"}
	}

	// Ed25519 public keys are exactly 32 bytes
	if len(xBytes) != ed25519.PublicKeySize {
		return &JWKValidationError{
			Message: fmt.Sprintf("invalid Ed25519 key length: %d bytes (expected %d)", len(xBytes), ed25519.PublicKeySize),
			Field:   "x",
		}
	}

	return nil
}

// ExtractJWKFromProtectedHeader extracts and validates JWK from JWS protected header
func ExtractJWKFromProtectedHeader(protectedB64 string) (*JWK, error) {
	// Decode protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid protected header encoding: %v", err)
	}

	// Parse protected header
	var protected struct {
		JWK *JWK `json:"jwk"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		return nil, fmt.Errorf("invalid protected header format: %v", err)
	}

	// For new account creation, JWK must be present (not kid)
	if protected.JWK == nil {
		if protected.Kid != "" {
			return nil, fmt.Errorf("new account creation must use 'jwk' field, not 'kid'")
		}
		return nil, fmt.Errorf("missing 'jwk' field in protected header")
	}

	// Validate the JWK
	if err := ValidateJWK(protected.JWK); err != nil {
		return nil, fmt.Errorf("invalid JWK: %v", err)
	}

	return protected.JWK, nil
}

// JWKToPublicKey converts a JWK to a Go crypto public key for verification
func JWKToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.KeyType {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECDSAPublicKey(jwk)
	case "OKP":
		return jwkToEd25519PublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus encoding: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent encoding: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func jwkToECDSAPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Curve != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Curve)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate encoding: %v", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate encoding: %v", err)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Verify point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func jwkToEd25519PublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Curve != "Ed25519" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Curve)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate encoding: %v", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key length: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

// SerializeJWK converts a JWK to JSON string for storage
func SerializeJWK(jwk *JWK) (string, error) {
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWK: %v", err)
	}
	return string(jwkBytes), nil
}

// DeserializeJWK converts a JSON string back to JWK
func DeserializeJWK(jwkJSON string) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return nil, fmt.Errorf("failed to deserialize JWK: %v", err)
	}
	return &jwk, nil
}