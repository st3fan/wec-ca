package main

import (
	"testing"
	"time"
)

func TestParseCertLifetime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "hours format",
			input:    "24h",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "days format",
			input:    "7d",
			expected: 7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "single day",
			input:    "1d",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "default 28 days",
			input:    "28d",
			expected: 28 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "complex hours format",
			input:    "72h",
			expected: 72 * time.Hour,
			wantErr:  false,
		},
		{
			name:    "invalid format - no suffix",
			input:   "24",
			wantErr: true,
		},
		{
			name:    "invalid format - wrong suffix",
			input:   "24x",
			wantErr: true,
		},
		{
			name:    "invalid format - non-numeric",
			input:   "abcd",
			wantErr: true,
		},
		{
			name:    "invalid days format",
			input:   "abcd",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCertLifetime(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCertLifetime(%q) expected error, got nil", tt.input)
				}
				return
			}
			
			if err != nil {
				t.Errorf("parseCertLifetime(%q) unexpected error: %v", tt.input, err)
				return
			}
			
			if result != tt.expected {
				t.Errorf("parseCertLifetime(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}