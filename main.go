package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	dataDir      = "data"
	caCertFile   = "data/ca.crt"
	caKeyFile    = "data/ca.key"
	serverCertFile = "data/server.crt"
	serverKeyFile  = "data/server.key"
	domain       = "sateh.systems"
	serverURL    = "https://acme.sateh.systems"
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
	r := mux.NewRouter()
	
	// Add logging middleware
	r.Use(logRequest)
	
	// ACME endpoints
	r.HandleFunc("/acme/home/directory", server.handleDirectory).Methods("GET")
	r.HandleFunc("/acme/home/new-nonce", server.handleNewNonce).Methods("HEAD", "GET")
	r.HandleFunc("/acme/home/new-account", server.handleNewAccount).Methods("POST")
	r.HandleFunc("/acme/home/new-order", server.handleNewOrder).Methods("POST")
	r.HandleFunc("/acme/home/order/{orderID}", server.handleOrder).Methods("POST")
	r.HandleFunc("/acme/home/finalize/{orderID}", server.handleFinalize).Methods("POST")
	r.HandleFunc("/acme/home/cert/{orderID}", server.handleCertificate).Methods("POST")
	
	// Static files
	r.HandleFunc("/ca.crt", server.handleCACert).Methods("GET")

	// Create TLS config with server certificate and CA chain
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{server.serverCert.Raw, server.caCert.Raw},
				PrivateKey:  server.serverKey,
			},
		},
	}

	log.Printf("Starting ACME server on :8443 (HTTPS)")
	log.Printf("CA Root certificate available at %s/ca.crt", serverURL)
	
	httpServer := &http.Server{
		Addr:      ":8443",
		Handler:   r,
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
			CommonName:   "acme." + domain,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"acme." + domain},
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

	log.Printf("Created new server certificate for acme.%s", domain)
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

	log.Printf("Loaded existing server certificate for acme.%s", domain)
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
	// Parse request (simplified)
	var req struct {
		Identifiers []Identifier `json:"identifiers"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", serverURL+"/acme/home/order/"+orderID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (s *ACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderID"]
	
	order, exists := s.orders[orderID]
	if !exists {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (s *ACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderID"]
	
	order, exists := s.orders[orderID]
	if !exists {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	// Parse CSR from request (simplified)
	var req struct {
		CSR string `json:"csr"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Issue certificate
	if err := s.issueCertificate(order); err != nil {
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	order.Status = "valid"
	order.Certificate = serverURL + "/acme/home/cert/" + orderID

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
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
		NotAfter:     time.Now().AddDate(0, 3, 0), // 3 months
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

	log.Printf("Issued certificate for %v", dnsNames)
	return nil
}

func (s *ACMEServer) handleCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderID"]

	certFile := filepath.Join(dataDir, orderID+".crt")
	certData, err := os.ReadFile(certFile)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

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