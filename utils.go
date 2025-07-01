package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func readCertificateFile(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %v", filename, err)
	}
	
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM from %s", filename)
	}
	
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %v", filename, err)
	}
	
	return cert, nil
}

func readPrivateKeyFile(filename string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %v", filename, err)
	}
	
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM from %s", filename)
	}
	
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %v", filename, err)
	}
	
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key from %s is not an RSA key", filename)
	}
	
	return rsaKey, nil
}