package clserver

import (
	"bytes"
	"hnproxy/internal/clbackend"
	"hnproxy/internal/clconfig"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestServer_DisplayConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *clconfig.ProxyConfig
	}{
		{
			name: "HTTP server",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Routes: map[string]*clbackend.BackendTarget{
					"test.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
		},
		{
			name: "HTTPS server with ACME",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				TLS: &clconfig.TLSConfig{
					Enabled: true,
					ACME: &clconfig.ACMEconfig{
						Email:    "test@example.com",
						Domains:  []string{"test.example.com"},
						CacheDir: "./certs",
					},
				},
				Routes: map[string]*clbackend.BackendTarget{
					"test.example.com": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clconfig.SetConfig(tt.config, true, true)
			// Créer un buffer pour capturer les logs
			var buf bytes.Buffer

			// Sauvegarder le logger global original
			originalLogger := zerolog.GlobalLevel()
			oldLogger := log.Logger

			// Créer un nouveau logger qui écrit dans le buffer
			log.Logger = zerolog.New(&buf).With().Timestamp().Logger()

			// Restaurer après le test
			defer func() {
				log.Logger = oldLogger
				zerolog.SetGlobalLevel(originalLogger)
			}()

			server := NewServer(tt.config)
			server.DisplayConfiguration("test-config.yaml")

			output := buf.String()

			// Les logs sont en JSON, on peut les parser ou juste vérifier le contenu
			if !strings.Contains(output, "hnProxy configuré") {
				t.Errorf("Output should contain 'hnProxy configuré', got: %s", output)
			}

			if !strings.Contains(output, "test-config.yaml") {
				t.Errorf("Output should contain 'test-config.yaml', got: %s", output)
			}

			if tt.config.TLS != nil && tt.config.TLS.Enabled {
				if !strings.Contains(output, "HTTPS activé") {
					t.Errorf("Output should indicate 'HTTPS activé', got: %s", output)
				}
			} else {
				if !strings.Contains(output, "Mode HTTP") {
					t.Errorf("Output should indicate 'Mode HTTP', got: %s", output)
				}
			}
		})
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Simple redirect",
			url:      "http://example.com/",
			expected: "https://www.example.com/",
		},
		{
			name:     "With path",
			url:      "http://example.com/api/users",
			expected: "https://www.example.com/api/users",
		},
		{
			name:     "With query params",
			url:      "http://example.com/search?q=test&page=1",
			expected: "https://www.example.com/search?q=test&page=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &clconfig.ProxyConfig{
				Redirection: map[string]string{
					"example.com": "www.example.com",
				},
				Routes: map[string]*clbackend.BackendTarget{
					"www.example.com": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			}
			clconfig.SetConfig(config, true, true)
			s := NewServer(config)
			req := httptest.NewRequest("GET", tt.url, nil)
			rr := httptest.NewRecorder()

			s.redirect(rr, req)

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
	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*clbackend.BackendTarget{
			"test.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL("http://127.0.0.1:3001"),
			}),
		},
	}
	clconfig.SetConfig(config, true, true)

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
