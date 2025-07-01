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

func (app *Application) handleNewNonce(w http.ResponseWriter, r *http.Request) {
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
	
	// RFC 8555: HEAD requests should return 200, GET requests should return 204
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// validateNonce extracts and validates the nonce from a JWS request
func (app *Application) validateNonce(w http.ResponseWriter, jwsReq map[string]interface{}) bool {
	protectedB64, ok := jwsReq["protected"].(string)
	if !ok {
		http.Error(w, "Missing or invalid protected header", http.StatusBadRequest)
		return false
	}

	// Decode the protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(protectedB64)
	if err != nil {
		http.Error(w, "Invalid protected header encoding", http.StatusBadRequest)
		return false
	}

	// Parse the protected header
	var protected struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		http.Error(w, "Invalid protected header format", http.StatusBadRequest)
		return false
	}

	// Validate the nonce
	if protected.Nonce == "" {
		http.Error(w, "Missing nonce in protected header", http.StatusBadRequest)
		return false
	}

	if !app.nonceStorage.IsValid(protected.Nonce) {
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

	// Parse JWS request
	var jwsReq map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jwsReq); err != nil {
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Validate nonce
	if !app.validateNonce(w, jwsReq) {
		return
	}

	// Validate JWS structure
	jwsRequest, err := ValidateJWSStructure(jwsReq)
	if err != nil {
		slog.Error("Invalid JWS structure", "error", err)
		http.Error(w, fmt.Sprintf("Invalid JWS: %v", err), http.StatusBadRequest)
		return
	}

	// Validate protected header and extract JWK
	expectedURL := app.settings.ServerURL + "/acme/new-account"
	header, err := ValidateProtectedHeader(jwsRequest.Protected, expectedURL)
	if err != nil {
		slog.Error("Protected header validation failed", "error", err)
		http.Error(w, fmt.Sprintf("Invalid protected header: %v", err), http.StatusBadRequest)
		return
	}

	jwk := header.JWK
	slog.Info("Successfully extracted JWK", "key_type", jwk.KeyType, "curve", jwk.Curve)

	// Validate algorithm matches key type
	if err := ValidateAlgorithmKeyMatch(header.Algorithm, jwk); err != nil {
		slog.Error("Algorithm/key mismatch", "error", err, "algorithm", header.Algorithm, "key_type", jwk.KeyType)
		http.Error(w, fmt.Sprintf("Algorithm/key mismatch: %v", err), http.StatusBadRequest)
		return
	}

	// Verify JWS signature
	if err := VerifyJWSSignature(jwsRequest, jwk); err != nil {
		slog.Error("JWS signature verification failed", "error", err, "algorithm", header.Algorithm)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	slog.Info("JWS signature verification successful", "algorithm", header.Algorithm)

	// Serialize JWK for storage
	jwkJSON, err := SerializeJWK(jwk)
	if err != nil {
		slog.Error("JWK serialization failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse payload to extract contact information
	payloadB64, ok := jwsReq["payload"].(string)
	if !ok {
		http.Error(w, "Missing or invalid payload", http.StatusBadRequest)
		return
	}

	var contact []string
	if payloadB64 != "" { // Empty payload is allowed for new account
		payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
		if err != nil {
			http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
			return
		}

		var payload struct {
			Contact []string `json:"contact,omitempty"`
		}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			// Ignore payload parsing errors for account creation - contact is optional
			slog.Info("Could not parse account payload", "error", err)
		} else {
			contact = payload.Contact
		}
	}

	accountID := strconv.FormatInt(time.Now().UnixNano(), 10)

	account := &Account{
		ID:      accountID,
		Status:  "valid",
		Contact: contact,
		Key:     jwkJSON, // Store validated JWK as JSON
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

	// Parse JWS request
	var jwsReq map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jwsReq); err != nil {
		slog.Error("Failed to parse JWS request", "error", err, "body", string(bodyBytes))
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Validate nonce
	if !app.validateNonce(w, jwsReq) {
		return
	}

	// Convert back to struct for easier access
	var jwsReqStruct struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(bodyBytes, &jwsReqStruct); err != nil {
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Decode the base64url payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwsReqStruct.Payload)
	if err != nil {
		slog.Error("Failed to decode payload", "error", err, "payload", jwsReqStruct.Payload)
		http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
		return
	}

	slog.Info("Decoded payload", "payload", string(payloadBytes))

	// Parse the actual request from the payload
	var req struct {
		Identifiers []Identifier `json:"identifiers"`
	}

	if err := json.Unmarshal(payloadBytes, &req); err != nil {
		slog.Error("Failed to parse payload JSON", "error", err, "payload", string(payloadBytes))
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

	// Parse JWS request for nonce validation
	var jwsReqMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jwsReqMap); err != nil {
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Validate nonce
	if !app.validateNonce(w, jwsReqMap) {
		return
	}

	// Convert back to struct for easier access
	var jwsReq struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(bodyBytes, &jwsReq); err != nil {
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Decode the base64url payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwsReq.Payload)
	if err != nil {
		http.Error(w, "Invalid payload encoding", http.StatusBadRequest)
		return
	}

	// Parse CSR from payload
	var req struct {
		CSR string `json:"csr"`
	}

	if err := json.Unmarshal(payloadBytes, &req); err != nil {
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