package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"net"
	"path/filepath"
	"strings"
	"time"
)

const (
	dataDir      = "data"
	caCertFile   = "data/ca.crt"
	caKeyFile    = "data/ca.key"
	serverCertFile = "data/server.crt"
	serverKeyFile  = "data/server.key"
)

var (
	hostname = mustGetEnv("WECCA_HOSTNAME")
	address  = getEnv("WECCA_ADDRESS", ":8443")
	domain   = mustGetEnv("WECCA_DOMAIN")
	certLifetime = parseCertLifetime(getEnv("WECCA_CERT_LIFETIME", "28d"))
	serverURL = buildServerURL(hostname, address)
)

type ACMEServer struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	serverCert *x509.Certificate
	serverKey  *rsa.PrivateKey
	accounts   map[string]*Account
	orders     map[string]*Order
}

type Account struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Key    string   `json:"key"`
}

type Order struct {
	ID           string        `json:"id"`
	Status       string        `json:"status"`
	Identifiers  []Identifier  `json:"identifiers"`
	Certificate  string        `json:"certificate,omitempty"`
	Finalize     string        `json:"finalize"`
	Authorizations []string    `json:"authorizations"`
	Expires      time.Time     `json:"expires"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required but not set", key)
	}
	return value
}

func buildServerURL(hostname, address string) string {
	// Extract host part from hostname (remove port if present)
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		// hostname doesn't contain a port, use as-is
		host = hostname
	}
	
	// Extract port from address
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		// If SplitHostPort fails, assume it's just a port like ":8443"
		if strings.HasPrefix(address, ":") {
			port = address[1:]
		} else {
			port = "443" // Default HTTPS port
		}
	}
	
	if port == "443" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}

func parseCertLifetime(lifetime string) time.Duration {
	if strings.HasSuffix(lifetime, "h") {
		hours, err := time.ParseDuration(lifetime)
		if err != nil {
			log.Fatalf("Invalid WECCA_CERT_LIFETIME format '%s': %v", lifetime, err)
		}
		return hours
	}
	
	if strings.HasSuffix(lifetime, "d") {
		daysStr := strings.TrimSuffix(lifetime, "d")
		days, err := time.ParseDuration(daysStr + "h")
		if err != nil {
			log.Fatalf("Invalid WECCA_CERT_LIFETIME format '%s': %v", lifetime, err)
		}
		return days * 24
	}
	
	log.Fatalf("Invalid WECCA_CERT_LIFETIME format '%s': must end with 'h' for hours or 'd' for days", lifetime)
	return 0
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		next.ServeHTTP(w, r)
		
		slog.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"duration", time.Since(start),
		)
	})
}

func main() {
	// Setup JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	
	server := &ACMEServer{
		accounts: make(map[string]*Account),
		orders:   make(map[string]*Order),
	}

	// Initialize CA and server certificate
	if err := server.initCA(); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	if err := server.initServerCert(); err != nil {
		log.Fatalf("Failed to initialize server certificate: %v", err)
	}

	// Setup routes
	mux := http.NewServeMux()
	
	// ACME endpoints
	mux.HandleFunc("GET /acme/home/directory", server.handleDirectory)
	mux.HandleFunc("HEAD /acme/home/new-nonce", server.handleNewNonce)
	mux.HandleFunc("GET /acme/home/new-nonce", server.handleNewNonce)
	mux.HandleFunc("POST /acme/home/new-account", server.handleNewAccount)
	mux.HandleFunc("POST /acme/home/new-order", server.handleNewOrder)
	mux.HandleFunc("POST /acme/home/order/{orderID}", server.handleOrder)
	mux.HandleFunc("POST /acme/home/finalize/{orderID}", server.handleFinalize)
	mux.HandleFunc("POST /acme/home/cert/{orderID}", server.handleCertificate)
	
	// Static files
	mux.HandleFunc("GET /ca.crt", server.handleCACert)
	
	// Wrap with logging middleware
	handler := logRequest(mux)

	// Create TLS config with server certificate and CA chain
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{server.serverCert.Raw, server.caCert.Raw},
				PrivateKey:  server.serverKey,
			},
		},
	}

	log.Printf("Starting ACME server on %s (HTTPS)", address)
	log.Printf("CA Root certificate available at %s/ca.crt", serverURL)
	
	httpServer := &http.Server{
		Addr:      address,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}

func (s *ACMEServer) initCA() error {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Check if CA already exists
	if _, err := os.Stat(caCertFile); err == nil {
		return s.loadCA()
	}

	return s.createCA()
}

func (s *ACMEServer) createCA() error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %v", err)
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"WEC CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{domain, "*." + domain},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Parse certificate
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Save CA certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(caCertFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	// Save CA private key
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(caKeyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save CA private key: %v", err)
	}

	s.caCert = caCert
	s.caKey = caKey

	log.Printf("Created new CA certificate for %s (valid for 10 years)", domain)
	return nil
}

func (s *ACMEServer) loadCA() error {
	// Load CA certificate
	certPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load CA private key
	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %v", err)
	}

	s.caCert = caCert
	s.caKey = caKey.(*rsa.PrivateKey)

	log.Printf("Loaded existing CA certificate for %s", domain)
	return nil
}

func (s *ACMEServer) initServerCert() error {
	// Check if server certificate already exists
	if _, err := os.Stat(serverCertFile); err == nil {
		return s.loadServerCert()
	}

	return s.createServerCert()
}

func (s *ACMEServer) createServerCert() error {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %v", err)
	}

	// Create server certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"WEC CA"},
			CommonName:   hostname,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &serverKey.PublicKey, s.caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %v", err)
	}

	// Parse certificate
	serverCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Save server certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(serverCertFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save server certificate: %v", err)
	}

	// Save server private key
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("failed to marshal server private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(serverKeyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save server private key: %v", err)
	}

	s.serverCert = serverCert
	s.serverKey = serverKey

	log.Printf("Created new server certificate for %s", hostname)
	return nil
}

func (s *ACMEServer) loadServerCert() error {
	// Load server certificate
	certPEM, err := os.ReadFile(serverCertFile)
	if err != nil {
		return fmt.Errorf("failed to read server certificate: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode server certificate PEM")
	}
	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Load server private key
	keyPEM, err := os.ReadFile(serverKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read server private key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode server private key PEM")
	}
	serverKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server private key: %v", err)
	}

	s.serverCert = serverCert
	s.serverKey = serverKey.(*rsa.PrivateKey)

	log.Printf("Loaded existing server certificate for %s", hostname)
	return nil
}

func (s *ACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	dir := Directory{
		NewNonce:   serverURL + "/acme/home/new-nonce",
		NewAccount: serverURL + "/acme/home/new-account",
		NewOrder:   serverURL + "/acme/home/new-order",
		RevokeCert: serverURL + "/acme/home/revoke-cert",
		KeyChange:  serverURL + "/acme/home/key-change",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dir)
}

func (s *ACMEServer) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	// Generate a simple nonce (in production, this should be more sophisticated)
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *ACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	// For this minimal implementation, we'll accept any account creation
	accountID := fmt.Sprintf("account_%d", time.Now().UnixNano())
	
	account := &Account{
		ID:     accountID,
		Status: "valid",
		Key:    "dummy_key", // In production, extract from JWS
	}
	
	s.accounts[accountID] = account

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", serverURL+"/acme/home/account/"+accountID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(account)
}

func (s *ACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	// Read the raw body first for logging
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	
	slog.Info("New order raw request", "body", string(bodyBytes), "content_type", r.Header.Get("Content-Type"))
	
	// Parse JWS request
	var jwsReq struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	
	if err := json.Unmarshal(bodyBytes, &jwsReq); err != nil {
		slog.Error("Failed to parse JWS request", "error", err, "body", string(bodyBytes))
		http.Error(w, "Invalid JWS request", http.StatusBadRequest)
		return
	}

	// Decode the base64url payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwsReq.Payload)
	if err != nil {
		slog.Error("Failed to decode payload", "error", err, "payload", jwsReq.Payload)
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
		if id.Type != "dns" || (!strings.HasSuffix(id.Value, "."+domain) && id.Value != domain) {
			http.Error(w, "Invalid identifier: only "+domain+" subdomains allowed", http.StatusBadRequest)
			return
		}
	}

	orderID := fmt.Sprintf("order_%d", time.Now().UnixNano())
	
	order := &Order{
		ID:          orderID,
		Status:      "ready", // Skip authorization for simplicity
		Identifiers: req.Identifiers,
		Finalize:    serverURL + "/acme/home/finalize/" + orderID,
		Expires:     time.Now().Add(24 * time.Hour),
	}
	
	s.orders[orderID] = order

	slog.Info("Generated order", "order", order)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", serverURL+"/acme/home/order/"+orderID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (s *ACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("orderID")
	
	order, exists := s.orders[orderID]
	if !exists {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (s *ACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	orderID := r.PathValue("orderID")
	
	order, exists := s.orders[orderID]
	if !exists {
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
	if err := s.issueCertificateFromCSR(order, req.CSR); err != nil {
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	order.Status = "valid"
	order.Certificate = serverURL + "/acme/home/cert/" + orderID

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (s *ACMEServer) issueCertificateFromCSR(order *Order, csrB64 string) error {
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
		NotAfter:     time.Now().Add(certLifetime),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}

	// Create certificate using the public key from the CSR
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
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

func (s *ACMEServer) issueCertificate(order *Order) error {
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
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(certLifetime),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &certKey.PublicKey, s.caKey)
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

func (s *ACMEServer) handleCertificate(w http.ResponseWriter, r *http.Request) {
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

func (s *ACMEServer) handleCACert(w http.ResponseWriter, r *http.Request) {
	certData, err := os.ReadFile(caCertFile)
	if err != nil {
		http.Error(w, "CA certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certData)
}