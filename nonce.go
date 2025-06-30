package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceGenerator defines the interface for generating nonces
type NonceGenerator interface {
	Generate() (string, error)
}

// NonceStorage defines the interface for storing and validating nonces
type NonceStorage interface {
	Store(nonce string) error
	IsValid(nonce string) bool
	Cleanup()
}

// CryptoNonceGenerator implements NonceGenerator using crypto/rand
type CryptoNonceGenerator struct {
	size int
}

// NewCryptoNonceGenerator creates a new CryptoNonceGenerator with the specified byte size
func NewCryptoNonceGenerator(size int) *CryptoNonceGenerator {
	return &CryptoNonceGenerator{size: size}
}

// Generate creates a cryptographically secure random nonce
func (g *CryptoNonceGenerator) Generate() (string, error) {
	bytes := make([]byte, g.size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// nonceEntry represents a stored nonce with its expiration time
type nonceEntry struct {
	expiry time.Time
}

// InMemoryNonceStorage implements NonceStorage using in-memory storage
type InMemoryNonceStorage struct {
	mu      sync.RWMutex
	nonces  map[string]nonceEntry
	ttl     time.Duration
	cleanup time.Duration
}

// NewInMemoryNonceStorage creates a new InMemoryNonceStorage
func NewInMemoryNonceStorage(ttl, cleanupInterval time.Duration) *InMemoryNonceStorage {
	storage := &InMemoryNonceStorage{
		nonces:  make(map[string]nonceEntry),
		ttl:     ttl,
		cleanup: cleanupInterval,
	}
	
	// Start cleanup goroutine
	go storage.cleanupExpired()
	
	return storage
}

// Store adds a nonce to the storage with expiration
func (s *InMemoryNonceStorage) Store(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.nonces[nonce] = nonceEntry{
		expiry: time.Now().Add(s.ttl),
	}
	
	return nil
}

// IsValid checks if a nonce is valid and removes it if it is (single use)
func (s *InMemoryNonceStorage) IsValid(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	entry, exists := s.nonces[nonce]
	if !exists {
		return false
	}
	
	// Check if expired
	if time.Now().After(entry.expiry) {
		delete(s.nonces, nonce)
		return false
	}
	
	// Nonce is valid, remove it (single use)
	delete(s.nonces, nonce)
	return true
}

// Cleanup removes expired nonces manually
func (s *InMemoryNonceStorage) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	for nonce, entry := range s.nonces {
		if now.After(entry.expiry) {
			delete(s.nonces, nonce)
		}
	}
}

// cleanupExpired runs in a goroutine to periodically clean up expired nonces
func (s *InMemoryNonceStorage) cleanupExpired() {
	ticker := time.NewTicker(s.cleanup)
	defer ticker.Stop()
	
	for range ticker.C {
		s.Cleanup()
	}
}