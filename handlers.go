package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func (app *Application) handleGetDirectory(w http.ResponseWriter, r *http.Request) {
	dir := Directory{
		NewNonce:   app.settings.ServerURL + "/acme/new-nonce",
		NewAccount: app.settings.ServerURL + "/acme/new-account",
		NewOrder:   app.settings.ServerURL + "/acme/new-order",
		RevokeCert: app.settings.ServerURL + "/acme/revoke-cert",
		KeyChange:  app.settings.ServerURL + "/acme/key-change",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dir)
}

func (app *Application) handleGetNewNonce(w http.ResponseWriter, r *http.Request) {
	// Generate cryptographically secure nonce
	nonce, err := app.nonceGen.Generate()
	if err != nil {
		slog.Error("Failed to generate nonce", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store nonce for validation
	if err := app.nonceStorage.Store(nonce); err != nil {
		slog.Error("Failed to store nonce", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (app *Application) handleHeadNewNonce(w http.ResponseWriter, r *http.Request) {
	// Generate cryptographically secure nonce
	nonce, err := app.nonceGen.Generate()
	if err != nil {
		slog.Error("Failed to generate nonce", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store nonce for validation
	if err := app.nonceStorage.Store(nonce); err != nil {
		slog.Error("Failed to store nonce", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// validateNonceFromHeader validates the nonce from a go-jose signature header
func (app *Application) validateNonceFromHeader(w http.ResponseWriter, header jose.Header) bool {
	nonce := header.Nonce
	if nonce == "" {
		http.Error(w, "Missing nonce in protected header", http.StatusBadRequest)
		return false
	}

	if !app.nonceStorage.IsValid(nonce) {
		// Generate a fresh nonce for the error response
		freshNonce, err := app.nonceGen.Generate()
		if err != nil {
			slog.Error("Failed to generate fresh nonce for error response", "error", err)
		} else {
			if err := app.nonceStorage.Store(freshNonce); err != nil {
				slog.Error("Failed to store fresh nonce for error response", "error", err)
			} else {
				w.Header().Set("Replay-Nonce", freshNonce)
			}
		}
		http.Error(w, "Invalid or reused nonce", http.StatusBadRequest)
		return false
	}

	return true
}

func (app *Application) handlePostNewAccount(w http.ResponseWriter, r *http.Request) {
	// Read the raw body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Parse JWS using go-jose
	jws, err := jose.ParseSigned(string(bodyBytes), []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	if err != nil {
		slog.Error("Failed to parse JWS", "error", err)
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Extract and validate protected header
	if len(jws.Signatures) != 1 {
		http.Error(w, "JWS must have exactly one signature", http.StatusBadRequest)
		return
	}

	header := jws.Signatures[0].Header

	slog.Info("JWS Header", "header", header)

	// Validate nonce from header
	nonce, ok := header.Nonce, header.Nonce != ""
	if !ok {
		http.Error(w, "Missing nonce in protected header", http.StatusBadRequest)
		return
	}

	if !app.nonceStorage.IsValid(nonce) {
		// Generate a fresh nonce for the error response
		freshNonce, err := app.nonceGen.Generate()
		if err != nil {
			slog.Error("Failed to generate fresh nonce for error response", "error", err)
		} else {
			if err := app.nonceStorage.Store(freshNonce); err != nil {
				slog.Error("Failed to store fresh nonce for error response", "error", err)
			} else {
				w.Header().Set("Replay-Nonce", freshNonce)
			}
		}
		http.Error(w, "Invalid or reused nonce", http.StatusBadRequest)
		return
	}

	// Validate URL
	expectedURL := app.settings.ServerURL + "/acme/new-account"
	if header.ExtraHeaders["url"] != expectedURL {
		http.Error(w, fmt.Sprintf("URL mismatch: expected %s, got %s", expectedURL, header.ExtraHeaders["url"]), http.StatusBadRequest)
		return
	}

	// Extract JWK from header
	if header.JSONWebKey == nil {
		// Check for kid field (not allowed for new account)
		if header.KeyID != "" {
			http.Error(w, "New account creation must use 'jwk' field, not 'kid'", http.StatusBadRequest)
			return
		}
		http.Error(w, "Missing 'jwk' field in protected header", http.StatusBadRequest)
		return
	}

	jwk := header.JSONWebKey
	slog.Info("Successfully extracted JWK", "key_type", jwk.Algorithm, "use", jwk.Use)

	// Verify JWS signature using go-jose
	payload, err := jws.Verify(jwk)
	if err != nil {
		slog.Error("JWS signature verification failed", "error", err, "algorithm", header.Algorithm)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	slog.Info("JWS signature verification successful", "algorithm", header.Algorithm)

	// Serialize JWK for storage
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		slog.Error("JWK serialization failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse payload to extract contact information
	var contact []string
	if len(payload) > 0 { // Empty payload is allowed for new account
		var payloadData struct {
			Contact []string `json:"contact,omitempty"`
		}
		if err := json.Unmarshal(payload, &payloadData); err != nil {
			// Ignore payload parsing errors for account creation - contact is optional
			slog.Info("Could not parse account payload", "error", err)
		} else {
			contact = payloadData.Contact
		}
	}

	accountID := strconv.FormatInt(time.Now().UnixNano(), 10)

	account := &Account{
		ID:      accountID,
		Status:  "valid",
		Contact: contact,
		Key:     string(jwkJSON), // Store validated JWK as JSON
	}

	if err := app.accountStorage.Create(account); err != nil {
		slog.Error("Failed to store account", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate a fresh nonce for the response
	freshNonce, err := app.nonceGen.Generate()
	if err != nil {
		slog.Error("Failed to generate fresh nonce for response", "error", err)
	} else {
		if err := app.nonceStorage.Store(freshNonce); err != nil {
			slog.Error("Failed to store fresh nonce for response", "error", err)
		} else {
			w.Header().Set("Replay-Nonce", freshNonce)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", app.settings.ServerURL+"/acme/account/"+accountID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(account)
}

func (app *Application) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountID")

	account, err := app.accountStorage.Read(accountID)
	if err != nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
}

func (app *Application) handlePostNewOrder(w http.ResponseWriter, r *http.Request) {
	// Read the raw body first for logging
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	slog.Info("New order raw request", "body", string(bodyBytes), "content_type", r.Header.Get("Content-Type"))

	// Parse JWS using go-jose
	jws, err := jose.ParseSigned(string(bodyBytes), []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	if err != nil {
		slog.Error("Failed to parse JWS", "error", err)
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Extract and validate protected header
	if len(jws.Signatures) != 1 {
		http.Error(w, "JWS must have exactly one signature", http.StatusBadRequest)
		return
	}

	header := jws.Signatures[0].Header

	// Validate nonce
	if !app.validateNonceFromHeader(w, header) {
		return
	}

	// We need a key to verify the signature - for new order, we expect 'kid' not 'jwk'
	// This is different from new account where we need 'jwk'
	// For now, let's skip signature verification for new order (simplified implementation)
	// In a full implementation, we'd look up the account key by 'kid'

	// Get payload without verification for now (simplified)
	payload := jws.UnsafePayloadWithoutVerification()

	slog.Info("Decoded payload", "payload", string(payload))

	// Parse the actual request from the payload
	var req struct {
		Identifiers []Identifier `json:"identifiers"`
	}

	if err := json.Unmarshal(payload, &req); err != nil {
		slog.Error("Failed to parse payload JSON", "error", err, "payload", string(payload))
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	slog.Info("New order request", "request", req)

	// Validate that all identifiers are subdomains of our domain
	for _, id := range req.Identifiers {
		if id.Type != "dns" || (!strings.HasSuffix(id.Value, "."+app.settings.Domain) && id.Value != app.settings.Domain) {
			http.Error(w, "Invalid identifier: only "+app.settings.Domain+" subdomains allowed", http.StatusBadRequest)
			return
		}
	}

	orderID := strconv.FormatInt(time.Now().UnixNano(), 10)

	order := &Order{
		ID:          orderID,
		Status:      "ready", // Skip authorization for simplicity
		Identifiers: req.Identifiers,
		Finalize:    app.settings.ServerURL + "/acme/finalize/" + orderID,
		Expires:     time.Now().Add(24 * time.Hour),
	}

	if err := app.orderStorage.Create(order); err != nil {
		slog.Error("Failed to store order", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	slog.Info("Generated order", "order", order)

	// Generate a fresh nonce for the response
	freshNonce, err := app.nonceGen.Generate()
	if err != nil {
		slog.Error("Failed to generate fresh nonce for response", "error", err)
	} else {
		if err := app.nonceStorage.Store(freshNonce); err != nil {
			slog.Error("Failed to store fresh nonce for response", "error", err)
		} else {
			w.Header().Set("Replay-Nonce", freshNonce)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", app.settings.ServerURL+"/acme/order/"+orderID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (app *Application) handleGetOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("orderID")

	order, err := app.orderStorage.Read(orderID)
	if err != nil {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (app *Application) handlePostFinalize(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("orderID")

	order, err := app.orderStorage.Read(orderID)
	if err != nil {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	// Read and decode JWS request
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Parse JWS using go-jose
	jws, err := jose.ParseSigned(string(bodyBytes), []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	if err != nil {
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Extract and validate protected header
	if len(jws.Signatures) != 1 {
		http.Error(w, "JWS must have exactly one signature", http.StatusBadRequest)
		return
	}

	header := jws.Signatures[0].Header

	// Validate nonce
	if !app.validateNonceFromHeader(w, header) {
		return
	}

	// Get payload without verification for now (simplified)
	payload := jws.UnsafePayloadWithoutVerification()

	// Parse CSR from payload
	var req struct {
		CSR string `json:"csr"`
	}

	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	slog.Info("Finalize request", "csr", req.CSR)

	// Issue certificate using the CSR
	if err := app.issueCertificateFromCSR(order, req.CSR); err != nil {
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	order.Status = "valid"
	order.Certificate = app.settings.ServerURL + "/acme/cert/" + orderID

	if err := app.orderStorage.Update(order); err != nil {
		slog.Error("Failed to update order", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate a fresh nonce for the response
	freshNonce, err := app.nonceGen.Generate()
	if err != nil {
		slog.Error("Failed to generate fresh nonce for response", "error", err)
	} else {
		if err := app.nonceStorage.Store(freshNonce); err != nil {
			slog.Error("Failed to store fresh nonce for response", "error", err)
		} else {
			w.Header().Set("Replay-Nonce", freshNonce)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (app *Application) handlePostCertificate(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("orderID")

	certFile := filepath.Join(dataDir, orderID+".crt")
	certData, err := os.ReadFile(certFile)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	// Return only the certificate (not the private key)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(certData)
}

func (app *Application) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	certData, err := os.ReadFile(caCertFile)
	if err != nil {
		http.Error(w, "CA certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certData)
}

func (app *Application) issueCertificateFromCSR(order *Order, csrB64 string) error {
	// Decode the base64url encoded CSR
	csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
	if err != nil {
		return fmt.Errorf("failed to decode CSR: %v", err)
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %v", err)
	}

	// Verify the CSR signature
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature verification failed: %v", err)
	}

	slog.Info("Parsed CSR", "subject", csr.Subject, "dns_names", csr.DNSNames)

	// Create certificate template from CSR
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(app.settings.CertLifetime),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}

	// Create certificate using the public key from the CSR
	certDER, err := x509.CreateCertificate(rand.Reader, &template, app.caCert, csr.PublicKey, app.caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile := filepath.Join(dataDir, order.ID+".crt")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	log.Printf("Issued certificate for %v", csr.DNSNames)
	return nil
}

func (app *Application) issueCertificate(order *Order) error {
	// Generate certificate private key
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate certificate key: %v", err)
	}

	// Extract DNS names from identifiers
	var dnsNames []string
	for _, id := range order.Identifiers {
		if id.Type == "dns" {
			dnsNames = append(dnsNames, id.Value)
		}
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"WEC CA"},
			CommonName:   dnsNames[0],
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(app.settings.CertLifetime),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, app.caCert, &certKey.PublicKey, app.caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile := filepath.Join(dataDir, order.ID+".crt")
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Save private key
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	keyFile := filepath.Join(dataDir, order.ID+".key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save certificate private key: %v", err)
	}

	log.Printf("Issued certificate for %v", dnsNames)
	return nil
}
