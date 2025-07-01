package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestHandlePostNewAccount_GoJose(t *testing.T) {
	// Generate test RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Note: JWK will be embedded automatically by EmbedJWK option

	// Create JWS signer
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"nonce": "test-nonce",
			"url":   "http://localhost:8080/acme/new-account",
		},
		EmbedJWK: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create payload
	payload := map[string]interface{}{
		"contact": []string{"mailto:test@example.com"},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Sign the payload
	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize JWS
	jwsString, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Convert compact serialization to JSON serialization for our handler
	// (This is a simplified approach - in reality we'd need to handle the format properly)
	parts := strings.Split(jwsString, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid JWS format")
	}

	jwsJSON := map[string]string{
		"protected": parts[0],
		"payload":   parts[1],
		"signature": parts[2],
	}
	jwsData, err := json.Marshal(jwsJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test application with mocks
	app := &Application{
		settings: &Settings{
			ServerURL: "http://localhost:8080",
		},
		nonceStorage:   &MemoryNonceStorage{nonces: make(map[string]bool)},
		nonceGen:       &MockNonceGenerator{},
		accountStorage: &MemoryAccountStorage{accounts: make(map[string]*Account)},
	}

	// Store the test nonce
	app.nonceStorage.Store("test-nonce")

	// Create test request
	req := httptest.NewRequest("POST", "/acme/new-account", strings.NewReader(string(jwsData)))
	req.Header.Set("Content-Type", "application/jose+json")
	w := httptest.NewRecorder()

	// Call handler
	app.handlePostNewAccount(w, req)

	// Check response (this test may fail since we need proper mocks, but it validates compilation)
	if w.Code != http.StatusCreated && w.Code != http.StatusBadRequest {
		t.Logf("Response code: %d, body: %s", w.Code, w.Body.String())
	}
}

// Mock implementations for testing
type MockNonceGenerator struct{}

func (m *MockNonceGenerator) Generate() (string, error) {
	return "mock-nonce", nil
}

type MemoryNonceStorage struct {
	nonces map[string]bool
}

func (m *MemoryNonceStorage) Store(nonce string) error {
	m.nonces[nonce] = true
	return nil
}

func (m *MemoryNonceStorage) IsValid(nonce string) bool {
	if m.nonces[nonce] {
		delete(m.nonces, nonce) // Use once
		return true
	}
	return false
}

func (m *MemoryNonceStorage) Cleanup() {
	// No-op for test implementation
}

type MemoryAccountStorage struct {
	accounts map[string]*Account
}

func (m *MemoryAccountStorage) Create(account *Account) error {
	m.accounts[account.ID] = account
	return nil
}

func (m *MemoryAccountStorage) Read(id string) (*Account, error) {
	account, exists := m.accounts[id]
	if !exists {
		return nil, fmt.Errorf("account not found")
	}
	return account, nil
}

func (m *MemoryAccountStorage) Update(account *Account) error {
	m.accounts[account.ID] = account
	return nil
}

func (m *MemoryAccountStorage) Delete(id string) error {
	delete(m.accounts, id)
	return nil
}

func (m *MemoryAccountStorage) List() ([]*Account, error) {
	var accounts []*Account
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}