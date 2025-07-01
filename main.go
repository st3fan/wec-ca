package main

import (
	"log"
	"log/slog"
	"os"
)

func main() {
	// Setup JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	
	// Load settings from environment
	settings, err := newSettingsFromEnv()
	if err != nil {
		log.Fatalf("Failed to load settings: %v", err)
	}
	
	// Create and run application
	app, err := newApplication(settings)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}
	
	if err := app.run(); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}