package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	dataDir        = "data"
	caCertFile     = "data/ca.crt"
	caKeyFile      = "data/ca.key"
	serverCertFile = "data/server.crt"
	serverKeyFile  = "data/server.key"
)

type Application struct {
	settings       *Settings
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	serverCert     *x509.Certificate
	serverKey      *rsa.PrivateKey
	accountStorage AccountStorage
	orderStorage   OrderStorage
	nonceGen       NonceGenerator
	nonceStorage   NonceStorage
}

type Account struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Key     string   `json:"key"`
}

type Order struct {
	ID             string       `json:"id"`
	Status         string       `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	Certificate    string       `json:"certificate,omitempty"`
	Finalize       string       `json:"finalize"`
	Authorizations []string     `json:"authorizations"`
	Expires        time.Time    `json:"expires"`
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

func newApplication(settings *Settings) (*Application, error) {
	accountStorage, err := NewFilesystemAccountStorage(filepath.Join(dataDir, "accounts"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize account storage: %v", err)
	}
	
	orderStorage, err := NewFilesystemOrderStorage(filepath.Join(dataDir, "orders"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize order storage: %v", err)
	}
	
	return &Application{
		settings:       settings,
		accountStorage: accountStorage,
		orderStorage:   orderStorage,
		nonceGen:       NewCryptoNonceGenerator(16), // 16 bytes = 128 bits of entropy
		nonceStorage:   NewInMemoryNonceStorage(time.Hour, 10*time.Minute), // 1 hour TTL, cleanup every 10 minutes
	}, nil
}

func (app *Application) run() error {
	// Initialize CA and server certificate
	if err := app.initCA(); err != nil {
		return fmt.Errorf("failed to initialize CA: %v", err)
	}

	if err := app.initServerCert(); err != nil {
		return fmt.Errorf("failed to initialize server certificate: %v", err)
	}

	// Setup routes
	mux := http.NewServeMux()

	// ACME endpoints
	mux.HandleFunc("GET /acme/directory", app.handleGetDirectory)
	mux.HandleFunc("HEAD /acme/new-nonce", app.handleHeadNewNonce)
	mux.HandleFunc("GET /acme/new-nonce", app.handleGetNewNonce)
	mux.HandleFunc("POST /acme/new-account", app.handlePostNewAccount)
	mux.HandleFunc("GET /acme/account/{accountID}", app.handleGetAccount)
	mux.HandleFunc("POST /acme/new-order", app.handlePostNewOrder)
	mux.HandleFunc("GET /acme/order/{orderID}", app.handleGetOrder)
	mux.HandleFunc("POST /acme/finalize/{orderID}", app.handlePostFinalize)
	mux.HandleFunc("POST /acme/cert/{orderID}", app.handlePostCertificate)

	// Static files
	mux.HandleFunc("GET /ca.crt", app.handleGetCACert)

	// Wrap with logging middleware
	handler := app.logRequest(mux)

	// Create TLS config with server certificate and CA chain
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{app.serverCert.Raw, app.caCert.Raw},
				PrivateKey:  app.serverKey,
			},
		},
	}

	log.Printf("Starting ACME server on %s (HTTPS)", app.settings.Address)
	log.Printf("CA Root certificate available at %s/ca.crt", app.settings.ServerURL)

	httpServer := &http.Server{
		Addr:      app.settings.Address,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	return httpServer.ListenAndServeTLS("", "")
}

func (app *Application) logRequest(next http.Handler) http.Handler {
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

func (app *Application) initCA() error {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Check if CA already exists
	if _, err := os.Stat(caCertFile); err == nil {
		return app.loadCA()
	}

	return app.createCA()
}

func (app *Application) createCA() error {
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
			CommonName:    app.settings.Domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{app.settings.Domain, "*." + app.settings.Domain},
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

	app.caCert = caCert
	app.caKey = caKey

	log.Printf("Created new CA certificate for %s (valid for 10 years)", app.settings.Domain)
	return nil
}

func (app *Application) loadCA() error {
	caCert, err := readCertificateFile(caCertFile)
	if err != nil {
		return err
	}

	caKey, err := readPrivateKeyFile(caKeyFile)
	if err != nil {
		return err
	}

	app.caCert = caCert
	app.caKey = caKey

	log.Printf("Loaded existing CA certificate for %s", app.settings.Domain)
	return nil
}

func (app *Application) initServerCert() error {
	// Check if server certificate already exists
	if _, err := os.Stat(serverCertFile); err == nil {
		return app.loadServerCert()
	}

	return app.createServerCert()
}

func (app *Application) createServerCert() error {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %v", err)
	}

	// Extract hostname without port
	hostname := app.settings.Hostname
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		// hostname doesn't contain a port, use as-is
		host = hostname
	}

	// Create server certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"WEC CA"},
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, app.caCert, &serverKey.PublicKey, app.caKey)
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

	app.serverCert = serverCert
	app.serverKey = serverKey

	log.Printf("Created new server certificate for %s", host)
	return nil
}

func (app *Application) loadServerCert() error {
	serverCert, err := readCertificateFile(serverCertFile)
	if err != nil {
		return err
	}

	serverKey, err := readPrivateKeyFile(serverKeyFile)
	if err != nil {
		return err
	}

	app.serverCert = serverCert
	app.serverKey = serverKey

	log.Printf("Loaded existing server certificate for %s", serverCert.Subject.CommonName)
	return nil
}