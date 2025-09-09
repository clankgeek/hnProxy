package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRedirectToHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Simple redirect",
			url:      "http://example.com/",
			expected: "https://example.com/",
		},
		{
			name:     "With path",
			url:      "http://example.com/api/users",
			expected: "https://example.com/api/users",
		},
		{
			name:     "With query params",
			url:      "http://example.com/search?q=test&page=1",
			expected: "https://example.com/search?q=test&page=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			rr := httptest.NewRecorder()

			redirectToHTTPS(rr, req)

			if rr.Code != http.StatusMovedPermanently {
				t.Errorf("redirectToHTTPS() status = %v, want %v", rr.Code, http.StatusMovedPermanently)
			}

			location := rr.Header().Get("Location")
			if location != tt.expected {
				t.Errorf("redirectToHTTPS() Location = %v, want %v", location, tt.expected)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	config := &ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*BackendTarget{
			"test.local": NewBackendTarget([]*url.URL{
				mustParseURL("http://127.0.0.1:3001"),
			}),
		},
	}

	server := NewServer(config)

	if server == nil {
		t.Fatal("NewServer() returned nil")
	}

	if server.config != config {
		t.Error("Server config not set correctly")
	}

	if server.handler == nil {
		t.Error("Server handler not created")
	}
}
