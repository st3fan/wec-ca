package main

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCryptoNonceGenerator_Generate(t *testing.T) {
	gen := NewCryptoNonceGenerator(16)

	t.Run("generates valid base64url encoded nonces", func(t *testing.T) {
		nonce, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate() returned error: %v", err)
		}

		// Should be valid base64url without padding
		_, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(nonce)
		if err != nil {
			t.Errorf("Generated nonce is not valid base64url: %v", err)
		}
	})

	t.Run("generates nonces of correct length", func(t *testing.T) {
		sizes := []int{8, 16, 32, 64}
		for _, size := range sizes {
			gen := NewCryptoNonceGenerator(size)
			nonce, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() returned error for size %d: %v", size, err)
			}

			// Decode to check byte length
			decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(nonce)
			if err != nil {
				t.Fatalf("Failed to decode nonce: %v", err)
			}

			if len(decoded) != size {
				t.Errorf("Expected decoded nonce length %d, got %d", size, len(decoded))
			}
		}
	})

	t.Run("generates unique nonces", func(t *testing.T) {
		const numNonces = 1000
		nonces := make(map[string]bool)

		for i := 0; i < numNonces; i++ {
			nonce, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() returned error at iteration %d: %v", i, err)
			}

			if nonces[nonce] {
				t.Errorf("Duplicate nonce generated: %s", nonce)
			}
			nonces[nonce] = true
		}

		if len(nonces) != numNonces {
			t.Errorf("Expected %d unique nonces, got %d", numNonces, len(nonces))
		}
	})

	t.Run("concurrent generation produces unique nonces", func(t *testing.T) {
		const numGoroutines = 10
		const noncesPerGoroutine = 100
		
		nonceChan := make(chan string, numGoroutines*noncesPerGoroutine)
		var wg sync.WaitGroup

		// Generate nonces concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < noncesPerGoroutine; j++ {
					nonce, err := gen.Generate()
					if err != nil {
						t.Errorf("Generate() returned error in goroutine: %v", err)
						return
					}
					nonceChan <- nonce
				}
			}()
		}

		wg.Wait()
		close(nonceChan)

		// Check for duplicates
		nonces := make(map[string]bool)
		for nonce := range nonceChan {
			if nonces[nonce] {
				t.Errorf("Duplicate nonce generated in concurrent test: %s", nonce)
			}
			nonces[nonce] = true
		}

		expectedCount := numGoroutines * noncesPerGoroutine
		if len(nonces) != expectedCount {
			t.Errorf("Expected %d unique nonces, got %d", expectedCount, len(nonces))
		}
	})
}

func TestInMemoryNonceStorage_Store(t *testing.T) {
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup() // Cleanup at end of test

	t.Run("stores nonce successfully", func(t *testing.T) {
		nonce := "test-nonce-123"
		err := storage.Store(nonce)
		if err != nil {
			t.Errorf("Store() returned error: %v", err)
		}

		// Verify it was stored by checking if it's valid
		if !storage.IsValid(nonce) {
			t.Error("Stored nonce should be valid")
		}
	})

	t.Run("allows storing multiple nonces", func(t *testing.T) {
		nonces := []string{"nonce1", "nonce2", "nonce3"}
		
		for _, nonce := range nonces {
			if err := storage.Store(nonce); err != nil {
				t.Errorf("Store() returned error for nonce %s: %v", nonce, err)
			}
		}

		// All should be valid (but will be consumed by IsValid)
		for _, nonce := range nonces {
			if !storage.IsValid(nonce) {
				t.Errorf("Nonce %s should be valid", nonce)
			}
		}
	})
}

func TestInMemoryNonceStorage_IsValid(t *testing.T) {
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup()

	t.Run("returns false for non-existent nonce", func(t *testing.T) {
		if storage.IsValid("non-existent") {
			t.Error("IsValid() should return false for non-existent nonce")
		}
	})

	t.Run("returns true for valid nonce and removes it", func(t *testing.T) {
		nonce := "valid-nonce"
		storage.Store(nonce)

		// First call should return true and consume the nonce
		if !storage.IsValid(nonce) {
			t.Error("IsValid() should return true for valid nonce")
		}

		// Second call should return false (single use)
		if storage.IsValid(nonce) {
			t.Error("IsValid() should return false for already used nonce")
		}
	})

	t.Run("returns false for expired nonce", func(t *testing.T) {
		// Create storage with very short TTL
		shortStorage := NewInMemoryNonceStorage(50*time.Millisecond, time.Minute)
		
		nonce := "expiring-nonce"
		shortStorage.Store(nonce)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		if shortStorage.IsValid(nonce) {
			t.Error("IsValid() should return false for expired nonce")
		}
	})
}

func TestInMemoryNonceStorage_Cleanup(t *testing.T) {
	storage := NewInMemoryNonceStorage(100*time.Millisecond, time.Hour) // Long cleanup interval

	t.Run("removes expired nonces", func(t *testing.T) {
		// Store some nonces
		nonces := []string{"nonce1", "nonce2", "nonce3"}
		for _, nonce := range nonces {
			storage.Store(nonce)
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Manual cleanup
		storage.Cleanup()

		// All nonces should now be invalid
		for _, nonce := range nonces {
			if storage.IsValid(nonce) {
				t.Errorf("Nonce %s should be expired and cleaned up", nonce)
			}
		}
	})

	t.Run("keeps valid nonces", func(t *testing.T) {
		longStorage := NewInMemoryNonceStorage(time.Hour, time.Hour)
		
		nonce := "valid-nonce"
		longStorage.Store(nonce)

		// Cleanup shouldn't remove valid nonces
		longStorage.Cleanup()

		if !longStorage.IsValid(nonce) {
			t.Error("Valid nonce should not be removed by cleanup")
		}
	})
}

func TestInMemoryNonceStorage_AutoCleanup(t *testing.T) {
	t.Run("automatically cleans up expired nonces", func(t *testing.T) {
		// Create storage with short TTL and cleanup interval
		storage := NewInMemoryNonceStorage(50*time.Millisecond, 100*time.Millisecond)
		
		nonce := "auto-cleanup-nonce"
		storage.Store(nonce)

		// Wait for expiration and auto-cleanup
		time.Sleep(200 * time.Millisecond)

		// Should be cleaned up automatically
		if storage.IsValid(nonce) {
			t.Error("Expired nonce should be automatically cleaned up")
		}
	})
}

func TestInMemoryNonceStorage_Concurrent(t *testing.T) {
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup()

	t.Run("handles concurrent store and validate operations", func(t *testing.T) {
		const numGoroutines = 10
		const operationsPerGoroutine = 100
		
		var wg sync.WaitGroup
		
		// Concurrent store operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					nonce := fmt.Sprintf("nonce-%d-%d", id, j)
					if err := storage.Store(nonce); err != nil {
						t.Errorf("Store() failed in goroutine %d: %v", id, err)
					}
				}
			}(i)
		}

		// Concurrent validate operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < operationsPerGoroutine; j++ {
					nonce := fmt.Sprintf("nonce-%d-%d", id, j)
					// Wait a bit to ensure store happens first
					time.Sleep(time.Millisecond)
					storage.IsValid(nonce) // Don't check result, just ensure no race condition
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("handles concurrent cleanup operations", func(t *testing.T) {
		const numCleanupGoroutines = 5
		var wg sync.WaitGroup

		// Store some nonces
		for i := 0; i < 100; i++ {
			storage.Store(fmt.Sprintf("cleanup-nonce-%d", i))
		}

		// Concurrent cleanup calls
		for i := 0; i < numCleanupGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				storage.Cleanup()
			}()
		}

		wg.Wait()
		// Test passes if no race condition occurs
	})
}

func TestNonceIntegration(t *testing.T) {
	t.Run("full workflow with generator and storage", func(t *testing.T) {
		gen := NewCryptoNonceGenerator(16)
		storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
		defer storage.Cleanup()

		// Generate and store multiple nonces
		const numNonces = 100
		var nonces []string

		for i := 0; i < numNonces; i++ {
			nonce, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() failed at iteration %d: %v", i, err)
			}

			if err := storage.Store(nonce); err != nil {
				t.Fatalf("Store() failed for nonce %s: %v", nonce, err)
			}

			nonces = append(nonces, nonce)
		}

		// Validate all nonces (should work once)
		for i, nonce := range nonces {
			if !storage.IsValid(nonce) {
				t.Errorf("Nonce %d should be valid: %s", i, nonce)
			}
		}

		// Try to validate again (should all fail - single use)
		for i, nonce := range nonces {
			if storage.IsValid(nonce) {
				t.Errorf("Nonce %d should not be valid on second use: %s", i, nonce)
			}
		}
	})
}

// Benchmark tests
func BenchmarkCryptoNonceGenerator_Generate(b *testing.B) {
	gen := NewCryptoNonceGenerator(16)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gen.Generate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInMemoryNonceStorage_Store(b *testing.B) {
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup()
	
	nonces := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		nonces[i] = fmt.Sprintf("bench-nonce-%d", i)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.Store(nonces[i])
	}
}

func BenchmarkInMemoryNonceStorage_IsValid(b *testing.B) {
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup()
	
	// Pre-populate with nonces
	nonces := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		nonces[i] = fmt.Sprintf("bench-nonce-%d", i)
		storage.Store(nonces[i])
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.IsValid(nonces[i])
	}
}

func BenchmarkNonceWorkflow(b *testing.B) {
	gen := NewCryptoNonceGenerator(16)
	storage := NewInMemoryNonceStorage(time.Hour, time.Minute)
	defer storage.Cleanup()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate
		nonce, err := gen.Generate()
		if err != nil {
			b.Fatal(err)
		}
		
		// Store
		storage.Store(nonce)
		
		// Validate (consumes)
		storage.IsValid(nonce)
	}
}

