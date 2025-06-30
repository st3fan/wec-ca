package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Settings struct {
	Hostname     string
	Address      string
	Domain       string
	CertLifetime time.Duration
	ServerURL    string
}

func newSettingsFromEnv() (*Settings, error) {
	settings := &Settings{}

	hostname := os.Getenv("WECCA_HOSTNAME")
	if hostname == "" {
		return nil, fmt.Errorf("WECCA_HOSTNAME is required but not set")
	}
	settings.Hostname = hostname

	address := os.Getenv("WECCA_ADDRESS")
	if address == "" {
		address = ":8443"
	}
	settings.Address = address

	domain := os.Getenv("WECCA_DOMAIN")
	if domain == "" {
		return nil, fmt.Errorf("WECCA_DOMAIN is required but not set")
	}
	settings.Domain = domain

	certLifetimeStr := os.Getenv("WECCA_CERT_LIFETIME")
	if certLifetimeStr == "" {
		certLifetimeStr = "28d"
	}
	
	certLifetime, err := parseCertLifetime(certLifetimeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid WECCA_CERT_LIFETIME: %v", err)
	}
	settings.CertLifetime = certLifetime

	settings.ServerURL = buildServerURL(hostname, address)

	return settings, nil
}

func parseCertLifetime(lifetime string) (time.Duration, error) {
	if strings.HasSuffix(lifetime, "h") {
		return time.ParseDuration(lifetime)
	}
	
	if strings.HasSuffix(lifetime, "d") {
		daysStr := strings.TrimSuffix(lifetime, "d")
		days, err := time.ParseDuration(daysStr + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid format '%s': %v", lifetime, err)
		}
		return days * 24, nil
	}
	
	return 0, fmt.Errorf("invalid format '%s': must end with 'h' for hours or 'd' for days", lifetime)
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