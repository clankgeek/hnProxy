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

func TestDisplayConfiguration_WithFirewall(t *testing.T) {
	tests := []struct {
		name   string
		config *clconfig.ProxyConfig
		check  string
	}{
		{
			name: "Firewall disabled",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Firewall: &clconfig.FirewallConfig{
					Enabled:              false,
					RateLimiter:          &clconfig.RateLimiterConfig{},
					Antibot:              &clconfig.AntiBotsConfig{},
					PatternsFiltering:    &clconfig.PatternsFilteringConfig{},
					SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{},
					GeolocationFiltering: &clconfig.GeolocationFilteringConfig{},
					IPBlockListConfig:    &clconfig.IPBlockListConfig{},
				},
				TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
				Routes: map[string]*clbackend.BackendTarget{
					"test.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
			check: "Firewall désactivé",
		},
		{
			name: "Firewall with rate limiter and antibot",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Firewall: &clconfig.FirewallConfig{
					Enabled:      true,
					BlockMessage: "teapot",
					RateLimiter:  &clconfig.RateLimiterConfig{Enabled: true, Limit: 50},
					Antibot: &clconfig.AntiBotsConfig{
						Enabled:           true,
						BlockLegitimeBots: true,
					},
					PatternsFiltering:  &clconfig.PatternsFilteringConfig{Enabled: true},
					SuspiciousBehavior: &clconfig.SuspiciousBehaviorConfig{Enabled: true},
					GeolocationFiltering: &clconfig.GeolocationFilteringConfig{
						Enabled: true,
					},
					IPBlockListConfig: &clconfig.IPBlockListConfig{
						Enabled:      true,
						DatabasePath: "/tmp/blocklist.txt",
					},
				},
				TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
				Routes: map[string]*clbackend.BackendTarget{
					"test.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
			check: "Firewall activé",
		},
		{
			name: "Firewall with IP blocklist URL",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Firewall: &clconfig.FirewallConfig{
					Enabled:              true,
					BlockMessage:         "notfound",
					RateLimiter:          &clconfig.RateLimiterConfig{Enabled: true, Limit: 100},
					Antibot:              &clconfig.AntiBotsConfig{},
					PatternsFiltering:    &clconfig.PatternsFilteringConfig{},
					SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{},
					GeolocationFiltering: &clconfig.GeolocationFilteringConfig{},
					IPBlockListConfig: &clconfig.IPBlockListConfig{
						Enabled:     true,
						DatabaseURL: "https://example.com/blocklist.txt",
					},
				},
				TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
				Routes: map[string]*clbackend.BackendTarget{
					"test.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
			check: "Firewall activé",
		},
		{
			name: "With redirection config",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Redirection: map[string]string{
					"old.local": "new.local",
				},
				Firewall: &clconfig.FirewallConfig{
					Enabled:              false,
					RateLimiter:          &clconfig.RateLimiterConfig{},
					Antibot:              &clconfig.AntiBotsConfig{},
					PatternsFiltering:    &clconfig.PatternsFilteringConfig{},
					SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{},
					GeolocationFiltering: &clconfig.GeolocationFilteringConfig{},
					IPBlockListConfig:    &clconfig.IPBlockListConfig{},
				},
				TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
				Routes: map[string]*clbackend.BackendTarget{
					"new.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
			check: "Redirection activée",
		},
		{
			name: "With slowfake block message",
			config: &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Firewall: &clconfig.FirewallConfig{
					Enabled:              true,
					BlockMessage:         "slowfake",
					RateLimiter:          &clconfig.RateLimiterConfig{Enabled: true},
					Antibot:              &clconfig.AntiBotsConfig{},
					PatternsFiltering:    &clconfig.PatternsFilteringConfig{},
					SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{},
					GeolocationFiltering: &clconfig.GeolocationFilteringConfig{},
					IPBlockListConfig:    &clconfig.IPBlockListConfig{},
				},
				TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
				Routes: map[string]*clbackend.BackendTarget{
					"app.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
			check: "slowfake",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			oldLogger := log.Logger
			log.Logger = zerolog.New(&buf).With().Timestamp().Logger()
			defer func() { log.Logger = oldLogger }()

			server := NewServer(tt.config)
			server.DisplayConfiguration("config.yaml")

			output := buf.String()
			if !strings.Contains(output, tt.check) {
				t.Errorf("output should contain %q, got: %s", tt.check, output)
			}
		})
	}
}

func TestNewServer_WithFirewall(t *testing.T) {
	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Firewall: &clconfig.FirewallConfig{
			Enabled:              true,
			RateLimiter:          &clconfig.RateLimiterConfig{Enabled: false},
			Antibot:              &clconfig.AntiBotsConfig{Enabled: false},
			PatternsFiltering:    &clconfig.PatternsFilteringConfig{Enabled: false},
			SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{Enabled: false},
			GeolocationFiltering: &clconfig.GeolocationFilteringConfig{Enabled: false},
			IPBlockListConfig:    &clconfig.IPBlockListConfig{Enabled: false},
		},
		TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
		Routes: map[string]*clbackend.BackendTarget{
			"test.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL("http://127.0.0.1:3001"),
			}),
		},
	}

	server := NewServer(config)
	if server == nil {
		t.Fatal("NewServer() returned nil")
	}
	defer server.Close()
}

func TestRedirectToHTTPS_AccessDenied(t *testing.T) {
	config := &clconfig.ProxyConfig{
		Redirection: map[string]string{},
		Firewall: &clconfig.FirewallConfig{
			Enabled:              false,
			RateLimiter:          &clconfig.RateLimiterConfig{},
			Antibot:              &clconfig.AntiBotsConfig{},
			PatternsFiltering:    &clconfig.PatternsFilteringConfig{},
			SuspiciousBehavior:   &clconfig.SuspiciousBehaviorConfig{},
			GeolocationFiltering: &clconfig.GeolocationFilteringConfig{},
			IPBlockListConfig:    &clconfig.IPBlockListConfig{},
		},
		Routes: map[string]*clbackend.BackendTarget{
			"valid.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL("http://127.0.0.1:3001"),
			}),
		},
		TLS: &clconfig.TLSConfig{ACME: &clconfig.ACMEconfig{}},
	}

	s := NewServer(config)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.local"
	req.RemoteAddr = "1.2.3.4:5678"
	rr := httptest.NewRecorder()

	s.redirect(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("redirect to unknown host should return 403, got %d", rr.Code)
	}
}
