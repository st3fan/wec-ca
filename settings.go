package main

import (
	"fmt"
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