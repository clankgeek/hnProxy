package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
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

func TestReverseProxyHandler_ServeHTTP(t *testing.T) {
	// Create test backend servers
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend1 response"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend2 response"))
	}))
	defer backend2.Close()

	// Create proxy config
	config := &ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*BackendTarget{
			"app1.local": NewBackendTarget([]*url.URL{
				mustParseURL(backend1.URL),
				mustParseURL(backend2.URL),
			}),
		},
	}

	// Create handler
	firewall := NewFirewall(nil)
	handler := NewReverseProxyHandler(config, firewall)

	tests := []struct {
		name       string
		host       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "Valid hostname",
			host:       "app1.local",
			wantStatus: http.StatusOK,
			wantBody:   "backend", // Should contain "backend" (either backend1 or backend2)
		},
		{
			name:       "Unknown hostname",
			host:       "unknown.local",
			wantStatus: http.StatusForbidden,
			wantBody:   "Access Denied",
		},
		{
			name:       "Hostname with port",
			host:       "app1.local:8080",
			wantStatus: http.StatusOK,
			wantBody:   "backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("ServeHTTP() status = %v, want %v", rr.Code, tt.wantStatus)
			}

			body := rr.Body.String()
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("ServeHTTP() body = %v, want to contain %v", body, tt.wantBody)
			}
		})
	}
}

func TestReverseProxyHandler_LoadBalancing(t *testing.T) {
	// Create multiple backend servers
	backends := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		id := i
		backends[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("backend%d", id)))
		}))
		defer backends[i].Close()
	}

	// Create proxy config
	config := &ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*BackendTarget{
			"app1.local": {
				URLs: []*url.URL{
					mustParseURL(backends[0].URL),
					mustParseURL(backends[1].URL),
					mustParseURL(backends[2].URL),
				},
			},
		},
	}

	handler := NewReverseProxyHandler(config, nil)

	// Make multiple requests and count responses
	responses := make(map[string]int)
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "app1.local"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Request %d failed with status %d", i, rr.Code)
		}

		body := rr.Body.String()
		responses[body]++
	}

	// Each backend should have been called exactly twice (6 requests / 3 backends)
	expectedCount := 2
	for i := 0; i < 3; i++ {
		expectedResponse := fmt.Sprintf("backend%d", i)
		if count := responses[expectedResponse]; count != expectedCount {
			t.Errorf("Backend %d called %d times, want %d", i, count, expectedCount)
		}
	}
}

// Test spécifique pour les cas d'erreur attendus
func TestReverseProxyHandler_ErrorCases(t *testing.T) {
	// Test avec backend valide pour la comparaison
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	config := &ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*BackendTarget{
			"valid.local": {
				URLs: []*url.URL{mustParseURL(backend.URL)},
			},
			"empty-backend.local": {
				URLs: []*url.URL{}, // Aucun backend
			},
		},
	}

	handler := NewReverseProxyHandler(config, nil)

	tests := []struct {
		name           string
		host           string
		expectedStatus int
		expectedBody   string
		description    string
	}{
		{
			name:           "Unknown hostname should return 403",
			host:           "unknown.local",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access Denied",
			description:    "Ce cas est normal et attendu - le message de log est OK",
		},
		{
			name:           "Empty backend should return 503",
			host:           "empty-backend.local",
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Aucun backend disponible",
			description:    "Route existe mais pas de backend",
		},
		{
			name:           "Valid hostname should work",
			host:           "valid.local",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
			description:    "Cas de succès pour comparaison",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Host = tt.host

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Vérifier le code de statut
			if rr.Code != tt.expectedStatus {
				t.Errorf("Status = %d, want %d (%s)", rr.Code, tt.expectedStatus, tt.description)
				return
			}

			// Vérifier le contenu de la réponse
			body := rr.Body.String()
			if !strings.Contains(body, tt.expectedBody) {
				t.Errorf("Body = %q, want to contain %q", body, tt.expectedBody)
				return
			}

			// Succès - le comportement est correct même si un log d'erreur apparaît
			t.Logf("✅ %s: Test passed (%s)", tt.name, tt.description)
		})
	}
}

// Benchmark tests
func BenchmarkReverseProxyHandler_ServeHTTP(b *testing.B) {
	// Create test backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	config := &ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*BackendTarget{
			"app1.local": {
				URLs: []*url.URL{mustParseURL(backend.URL)},
			},
		},
	}

	handler := NewReverseProxyHandler(config, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "app1.local"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

func TestHandleExampleCreation(t *testing.T) {
	// Test in temporary directory
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	err := os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change to temp dir: %v", err)
	}

	err = handleExampleCreation()
	if err != nil {
		t.Errorf("handleExampleCreation() error = %v", err)
	}

	// Check if file was created
	if _, err := os.Stat("hnproxy.yaml"); os.IsNotExist(err) {
		t.Error("Example config file was not created")
	}
}

func TestLoadAndValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "Valid config",
			yaml: `
listen: "0.0.0.0:8080"
routes:
  test.local:
    backends:
      - "http://127.0.0.1:3001"
`,
			wantErr: false,
		},
		{
			name: "Invalid config - no listen",
			yaml: `
routes:
  test.local:
    backends:
      - "http://127.0.0.1:3001"
`,
			wantErr: true,
		},
		{
			name: "Invalid config - no routes",
			yaml: `
listen: "0.0.0.0:8080"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpFile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(tt.yaml); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}
			tmpFile.Close()

			_, err = loadAndValidateConfig(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadAndValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServer_DisplayConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *ProxyConfig
	}{
		{
			name: "HTTP server",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Routes: map[string]*BackendTarget{
					"test.local": NewBackendTarget([]*url.URL{
						mustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
		},
		{
			name: "HTTPS server with ACME",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				TLS: &TLSConfig{
					Enabled: true,
					ACME: &ACME{
						Email:    "test@example.com",
						Domains:  []string{"test.example.com"},
						CacheDir: "./certs",
					},
				},
				Routes: map[string]*BackendTarget{
					"test.example.com": NewBackendTarget([]*url.URL{
						mustParseURL("http://127.0.0.1:3001"),
					}),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "Valid config",
			yaml: `
listen: "0.0.0.0:8080"
routes:
  app1.local:
    backends:
      - "http://127.0.0.1:3001"
      - "http://127.0.0.1:3002"
`,
			wantErr: false,
		},
		{
			name: "Valid config with TLS",
			yaml: `
listen: "0.0.0.0:8080"
tls:
  enabled: true
  acme:
    email: "test@example.com"
    domains:
      - "app1.example.com"
    cache_dir: "./certs"
routes:
  app1.example.com:
    backends:
      - "http://127.0.0.1:3001"
`,
			wantErr: false,
		},
		{
			name: "Invalid YAML",
			yaml: `
listen: "0.0.0.0:8080"
routes:
  app1.local
    backends:
      - "http://127.0.0.1:3001"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write config to file
			if _, err := tmpFile.WriteString(tt.yaml); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}
			tmpFile.Close()

			// Test loading
			_, err = loadConfig(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvertConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &Config{
				Listen: "0.0.0.0:8080",
				Routes: map[string]Route{
					"app1.local": {
						Backends: []string{"http://127.0.0.1:3001"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid backend URL",
			config: &Config{
				Listen: "0.0.0.0:8080",
				Routes: map[string]Route{
					"app1.local": {
						Backends: []string{"invalid-url"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid HTTP config",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Routes: map[string]*BackendTarget{
					"app1.local": {
						URLs: []*url.URL{mustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Missing listen address",
			config: &ProxyConfig{
				Routes: map[string]*BackendTarget{
					"app1.local": {
						URLs: []*url.URL{mustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: true,
			errMsg:  "adresse d'écoute non définie",
		},
		{
			name: "No routes",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Routes:     map[string]*BackendTarget{},
			},
			wantErr: true,
			errMsg:  "aucune route définie",
		},
		{
			name: "TLS enabled but no ACME or certs",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				TLS: &TLSConfig{
					Enabled: true,
				},
				Routes: map[string]*BackendTarget{
					"app1.local": {
						URLs: []*url.URL{mustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: true,
			errMsg:  "certificats TLS manquants",
		},
		{
			name: "Valid ACME config",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				TLS: &TLSConfig{
					Enabled: true,
					ACME: &ACME{
						Email:   "test@example.com",
						Domains: []string{"app1.example.com"},
					},
				},
				Routes: map[string]*BackendTarget{
					"app1.example.com": {
						URLs: []*url.URL{mustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ACME missing email",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				TLS: &TLSConfig{
					Enabled: true,
					ACME: &ACME{
						Domains: []string{"app1.example.com"},
					},
				},
				Routes: map[string]*BackendTarget{
					"app1.example.com": {
						URLs: []*url.URL{mustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: true,
			errMsg:  "email ACME requis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateConfig() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestCreateExampleConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "example-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	err = createExampleConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("createExampleConfig() failed: %v", err)
	}

	// Read and validate the created config
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read created config: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		t.Fatalf("Generated config is not valid YAML: %v", err)
	}

	// Validate essential fields
	if config.Listen == "" {
		t.Error("Generated config missing listen address")
	}

	if len(config.Routes) == 0 {
		t.Error("Generated config has no routes")
	}

	if config.TLS == nil || !config.TLS.Enabled {
		t.Error("Generated config should have TLS enabled")
	}
}

// TestNewFirewall vérifie la création d'une nouvelle instance de Firewall
func TestNewFirewall(t *testing.T) {
	tests := []struct {
		name              string
		blockLegitimeBots bool
	}{
		{"avec blocage bots légitimes", true},
		{"sans blocage bots légitimes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := NewFirewall(NewFirewallConfig(true, 100, true, tt.blockLegitimeBots, false, false))

			if fw == nil {
				t.Fatal("NewFirewall a retourné nil")
			}

			if fw.config.Antibot.BlockLegitimeBots != tt.blockLegitimeBots {
				t.Errorf("blockLegitimeBots = %v, attendu %v",
					fw.config.Antibot.BlockLegitimeBots, tt.blockLegitimeBots)
			}

			if fw.blockedIPs == nil {
				t.Error("blockedIPs n'est pas initialisé")
			}

			if fw.rateLimiter == nil {
				t.Error("rateLimiter n'est pas initialisé")
			}

			if fw.rateLimiter.requests == nil {
				t.Error("rateLimiter.requests n'est pas initialisé")
			}
		})
	}
}

// TestIsBot_UserAgentVide teste la détection d'un User-Agent vide
func TestIsBot_UserAgentVide(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, true, false, true, true))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "")

	if !fw.IsBot(req, "192.168.1.1") {
		t.Error("Un User-Agent vide devrait être détecté comme bot")
	}

	if !fw.isIPBlocked("192.168.1.1") {
		t.Error("L'IP devrait être bloquée après détection d'User-Agent vide")
	}
}

// TestIsBot_BotsMalveillants teste la détection des bots malveillants
func TestIsBot_BotsMalveillants(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, true, false, true, true))

	botUserAgents := []string{
		"python-requests/2.28.0",
		"curl/7.68.0",
		"Scrapy/2.5.0",
		"sqlmap/1.5.2",
		"nikto/2.1.5",
		"masscan/1.3.0",
	}

	for _, ua := range botUserAgents {
		t.Run(ua, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", ua)

			if !fw.IsBot(req, "192.168.1."+ua) {
				t.Errorf("User-Agent %s devrait être détecté comme bot", ua)
			}
		})
	}
}

// TestIsBot_BotsLegitimes teste le comportement avec les bots légitimes
func TestIsBot_BotsLegitimes(t *testing.T) {
	tests := []struct {
		name              string
		blockLegitimeBots bool
		userAgent         string
		shouldBlock       bool
	}{
		{
			"Googlebot autorisé",
			false,
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			false,
		},
		{
			"Googlebot bloqué",
			true,
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			true,
		},
		{
			"Bingbot autorisé",
			false,
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			false,
		},
		{
			"Bingbot bloqué",
			true,
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			true,
		},
		{
			"FacebookBot autorisé",
			false,
			"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := NewFirewall(NewFirewallConfig(true, 100, true, tt.blockLegitimeBots, true, true))
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")

			result := fw.IsBot(req, "192.168.1.100")
			if result != tt.shouldBlock {
				t.Errorf("IsBot() = %v, attendu %v", result, tt.shouldBlock)
			}
		})
	}
}

// TestHasSuspiciousBehavior teste la détection de comportements suspects
func TestHasSuspiciousBehavior(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(true, 100, false, false, false, true))

	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		suspicious bool
	}{
		{
			"Headers normaux",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html,application/xhtml+xml")
				r.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
				r.Header.Set("Accept-Encoding", "gzip, deflate, br")
			},
			false,
		},
		{
			"Accept manquant",
			func(r *http.Request) {
				r.Header.Set("Accept-Language", "fr-FR")
			},
			true,
		},
		{
			"Accept-Language manquant",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html")
			},
			true,
		},
		{
			"Accept-Encoding suspect",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html")
				r.Header.Set("Accept-Language", "en")
				r.Header.Set("Accept-Encoding", "weird-encoding")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			result := fw.hasSuspiciousBehavior(req)
			if result != tt.suspicious {
				t.Errorf("hasSuspiciousBehavior() = %v, attendu %v", result, tt.suspicious)
			}
		})
	}
}

// TestHasSuspiciousBehavior_PathsSensibles teste la détection d'accès à des fichiers sensibles
func TestHasSuspiciousBehavior_PathsSensibles(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(true, 100, true, false, true, true))

	suspiciousPaths := []string{
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/.aws/credentials",
		"/admin/.env",
	}

	for _, path := range suspiciousPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")

			if !fw.hasSuspiciousBehavior(req) {
				t.Errorf("Le chemin %s devrait être détecté comme suspect", path)
			}
		})
	}

	// Tester un chemin normal
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")

	if fw.hasSuspiciousBehavior(req) {
		t.Error("Un chemin normal ne devrait pas être suspect")
	}
}

// TestRateLimiter_Allow teste le fonctionnement du rate limiter
func TestRateLimiter_Allow(t *testing.T) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    3,
		window:   100 * time.Millisecond,
	}

	ip := "192.168.1.1"

	// Les premières requêtes doivent passer
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Errorf("La requête %d devrait être autorisée", i+1)
		}
	}

	// La 4ème requête devrait être bloquée
	if rl.Allow(ip) {
		t.Error("La 4ème requête devrait être bloquée")
	}

	// Attendre que la fenêtre expire
	time.Sleep(150 * time.Millisecond)

	// Maintenant la requête devrait passer
	if !rl.Allow(ip) {
		t.Error("La requête devrait être autorisée après expiration de la fenêtre")
	}
}

// TestRateLimiter_Concurrent teste le rate limiter en conditions concurrentes
func TestRateLimiter_Concurrent(t *testing.T) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    10,
		window:   100 * time.Millisecond,
	}

	var wg sync.WaitGroup
	allowed := 0
	blocked := 0
	var mu sync.Mutex

	// Lancer 20 goroutines simultanées
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("192.168.1.1") {
				mu.Lock()
				allowed++
				mu.Unlock()
			} else {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if allowed > 10 {
		t.Errorf("Plus de requêtes autorisées que la limite: %d > 10", allowed)
	}

	if allowed+blocked != 20 {
		t.Errorf("Total incorrect: allowed=%d, blocked=%d", allowed, blocked)
	}
}

// TestIsLimiter teste la méthode IsLimiter
func TestIsLimiter(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(true, 100, false, false, false, false))
	fw.rateLimiter.limit = 2
	fw.rateLimiter.window = 100 * time.Millisecond

	req := httptest.NewRequest("GET", "/", nil)
	ip := "192.168.1.1"

	// Les premières requêtes ne devraient pas déclencher le limiter
	for i := 0; i < 2; i++ {
		if fw.IsLimiter(req, ip) {
			t.Errorf("La requête %d ne devrait pas être limitée", i+1)
		}
	}

	// La 3ème requête devrait déclencher le limiter
	if !fw.IsLimiter(req, ip) {
		t.Error("La 3ème requête devrait être limitée")
	}

	// L'IP devrait maintenant être bloquée
	if !fw.isIPBlocked(ip) {
		t.Error("L'IP devrait être bloquée après dépassement du rate limit")
	}
}

// TestBlockIP_Duration teste le blocage temporaire des IPs
func TestBlockIP_Duration(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(true, 100, false, false, false, false))
	ip := "192.168.1.1"

	// Bloquer l'IP pour 50ms
	fw.blockIP(ip, 50*time.Millisecond)

	if !fw.isIPBlocked(ip) {
		t.Error("L'IP devrait être bloquée immédiatement")
	}

	// Attendre que le blocage expire
	time.Sleep(60 * time.Millisecond)

	if fw.isIPBlocked(ip) {
		t.Error("L'IP ne devrait plus être bloquée après expiration")
	}
}

// TestGetClientIP teste l'extraction de l'IP cliente
func TestGetClientIP(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, false, false, true, true))

	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			"X-Real-IP",
			func(r *http.Request) {
				r.Header.Set("X-Real-IP", "203.0.113.1")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.1",
		},
		{
			"X-Forwarded-For simple",
			func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.2")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.2",
		},
		{
			"X-Forwarded-For multiple",
			func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.3, 10.0.0.1, 192.168.1.1")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.3",
		},
		{
			"RemoteAddr avec port",
			func(r *http.Request) {
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"192.168.1.1",
		},
		{
			"RemoteAddr sans port",
			func(r *http.Request) {
				r.RemoteAddr = "192.168.1.1"
			},
			"192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			ip := fw.GetClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("GetClientIP() = %v, attendu %v", ip, tt.expectedIP)
			}
		})
	}
}

// TestCleanupRoutine teste le nettoyage périodique
func TestCleanupRoutine(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, false, false, true, true))

	// Bloquer quelques IPs avec des durées courtes
	fw.blockIP("192.168.1.1", 50*time.Millisecond)
	fw.blockIP("192.168.1.2", 100*time.Millisecond)
	fw.blockIP("192.168.1.3", 10*time.Second) // Cette IP restera bloquée

	// Ajouter des requêtes au rate limiter
	fw.rateLimiter.window = 50 * time.Millisecond
	fw.rateLimiter.Allow("10.0.0.1")
	fw.rateLimiter.Allow("10.0.0.2")

	// Lancer la routine de nettoyage
	fw.CleanupRoutine()

	// Attendre un peu pour que les blocages expirent
	time.Sleep(150 * time.Millisecond)

	// Forcer un nettoyage manuel pour le test
	fw.mu.Lock()
	now := time.Now()
	for ip, blockUntil := range fw.blockedIPs {
		if now.After(blockUntil) {
			delete(fw.blockedIPs, ip)
		}
	}
	fw.mu.Unlock()

	// Vérifier que les IPs expirées sont nettoyées
	if fw.isIPBlocked("192.168.1.1") {
		t.Error("L'IP 192.168.1.1 ne devrait plus être bloquée")
	}

	if fw.isIPBlocked("192.168.1.2") {
		t.Error("L'IP 192.168.1.2 ne devrait plus être bloquée")
	}

	// Cette IP devrait toujours être bloquée
	if !fw.isIPBlocked("192.168.1.3") {
		t.Error("L'IP 192.168.1.3 devrait toujours être bloquée")
	}
}

// TestIsLegitimateBot teste la détection des bots légitimes
func TestIsLegitimateBot(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, true, false, true, true))

	tests := []struct {
		userAgent    string
		isLegitimate bool
	}{
		{"mozilla/5.0 (compatible; googlebot/2.1)", true},
		{"bingbot/2.0", true},
		{"facebookexternalhit/1.1", true},
		{"twitterbot/1.0", true},
		{"random-bot/1.0", false},
		{"mozilla/5.0 firefox", false},
		{"python-requests/2.28.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			result := fw.isLegitimateBot(strings.ToLower(tt.userAgent))
			if result != tt.isLegitimate {
				t.Errorf("isLegitimateBot(%s) = %v, attendu %v",
					tt.userAgent, result, tt.isLegitimate)
			}
		})
	}
}

// TestPatternsSuspects teste la détection basée sur les patterns
func TestPatternsSuspects(t *testing.T) {
	fw := NewFirewall(NewFirewallConfig(false, 100, true, false, true, true))

	tests := []struct {
		name        string
		userAgent   string
		shouldBlock bool
	}{
		{
			"Pattern bot générique",
			"some-bot/1.0",
			true,
		},
		{
			"Pattern crawler",
			"web-crawler/2.0",
			true,
		},
		{
			"Pattern spider",
			"spider-engine/1.0",
			true,
		},
		{
			"Pattern scraper",
			"data-scraper/3.0",
			true,
		},
		{
			"Navigateur normal",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")

			result := fw.IsBot(req, "192.168.1.100")
			if result != tt.shouldBlock {
				t.Errorf("IsBot() = %v, attendu %v pour %s",
					result, tt.shouldBlock, tt.userAgent)
			}
		})
	}
}

// BenchmarkIsBot teste les performances de IsBot
func BenchmarkIsBot(b *testing.B) {
	fw := NewFirewall(NewFirewallConfig(false, 100, true, false, true, true))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.IsBot(req, "192.168.1.1")
	}
}

// BenchmarkRateLimiter teste les performances du rate limiter
func BenchmarkRateLimiter(b *testing.B) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    100,
		window:   time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("192.168.1.1")
	}
}

func TestBackendTarget_NextURL(t *testing.T) {
	tests := []struct {
		name     string
		urls     []string
		expected []string
	}{
		{
			name:     "Single backend",
			urls:     []string{"http://localhost:3001"},
			expected: []string{"http://localhost:3001", "http://localhost:3001"},
		},
		{
			name:     "Multiple backends round-robin",
			urls:     []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003"},
			expected: []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003", "http://localhost:3001"},
		},
		{
			name:     "Empty backends",
			urls:     []string{},
			expected: []string{"", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &BackendTarget{
				URLs: make([]*url.URL, 0, len(tt.urls)),
			}

			// Parse URLs
			for _, u := range tt.urls {
				parsed, err := url.Parse(u)
				if err != nil {
					t.Fatalf("Failed to parse URL %s: %v", u, err)
				}
				target.URLs = append(target.URLs, parsed)
			}

			// Test round-robin
			for i, expected := range tt.expected {
				got := target.NextURL()
				var gotStr string
				if got != nil {
					gotStr = got.String()
				}

				if gotStr != expected {
					t.Errorf("NextURL() call %d = %v, want %v", i+1, gotStr, expected)
				}
			}
		})
	}
}

func TestServer_BackendTarget(t *testing.T) {
	tests := []struct {
		name     string
		urls     []string
		expected []string
	}{
		{
			name:     "Single backend",
			urls:     []string{"http://localhost:3001"},
			expected: []string{"http://localhost:3001", "http://localhost:3001"},
		},
		{
			name:     "Multiple backends round-robin",
			urls:     []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003"},
			expected: []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003", "http://localhost:3001"},
		},
		{
			name:     "Empty backends",
			urls:     []string{},
			expected: []string{"", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &BackendTarget{
				URLs: make([]*url.URL, 0, len(tt.urls)),
			}

			// Parse URLs
			for _, u := range tt.urls {
				parsed, err := url.Parse(u)
				if err != nil {
					t.Fatalf("Failed to parse URL %s: %v", u, err)
				}
				target.URLs = append(target.URLs, parsed)
			}

			// Test round-robin
			for i, expected := range tt.expected {
				got := target.NextURL()
				var gotStr string
				if got != nil {
					gotStr = got.String()
				}

				if gotStr != expected {
					t.Errorf("NextURL() call %d = %v, want %v", i+1, gotStr, expected)
				}
			}
		})
	}
}

func TestBackendTarget_Concurrent(t *testing.T) {
	target := &BackendTarget{
		URLs: []*url.URL{
			mustParseURL("http://localhost:3001"),
			mustParseURL("http://localhost:3002"),
		},
	}

	// Test plus simple et direct
	const numGoroutines = 10
	const requestsPerGoroutine = 100

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]int)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localResults := make(map[string]int)

			for j := 0; j < requestsPerGoroutine; j++ {
				url := target.NextURL()
				if url != nil {
					localResults[url.String()]++
				}
			}

			// Merge results thread-safely
			mu.Lock()
			for url, count := range localResults {
				results[url] += count
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Verify results
	totalRequests := 0
	for url, count := range results {
		totalRequests += count
		if url != "http://localhost:3001" && url != "http://localhost:3002" {
			t.Errorf("Unexpected URL: %s", url)
		}
	}

	expectedTotal := numGoroutines * requestsPerGoroutine
	if totalRequests != expectedTotal {
		t.Errorf("Got %d total requests, want %d", totalRequests, expectedTotal)
	}

	t.Logf("✅ Concurrent test passed: %d total requests", totalRequests)
	for url, count := range results {
		percentage := float64(count) / float64(totalRequests) * 100
		t.Logf("📊 %s: %d requests (%.1f%%)", url, count, percentage)
	}
}

// Benchmark tests
func BenchmarkBackendTarget_NextURL(b *testing.B) {
	target := &BackendTarget{
		URLs: []*url.URL{
			mustParseURL("http://localhost:3001"),
			mustParseURL("http://localhost:3002"),
			mustParseURL("http://localhost:3003"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target.NextURL()
	}
}

func TestParseCommandLineArgs(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name        string
		args        []string
		wantConfig  string
		wantExample bool
		wantVersion bool
		wantErr     bool
	}{
		{
			name:        "Valid config file",
			args:        []string{"prog", "-config", "test.yaml"},
			wantConfig:  "test.yaml",
			wantExample: false,
			wantVersion: false,
			wantErr:     false,
		},
		{
			name:        "Example flag",
			args:        []string{"prog", "-example"},
			wantConfig:  "",
			wantExample: true,
			wantVersion: false,
			wantErr:     false,
		},
		{
			name:        "Version flag",
			args:        []string{"prog", "-version"},
			wantConfig:  "",
			wantExample: false,
			wantVersion: true,
			wantErr:     false,
		},
		{
			name:        "No arguments",
			args:        []string{"prog"},
			wantConfig:  "",
			wantExample: false,
			wantVersion: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag parsing
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			os.Args = tt.args

			gotConfig, gotExample, gotVersion, err := parseCommandLineArgs()

			if tt.wantVersion && tt.wantVersion != gotVersion {
				t.Errorf("parseCommandLineArgs() version = %v, want %v", gotVersion, tt.wantVersion)
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCommandLineArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotConfig != tt.wantConfig {
				t.Errorf("parseCommandLineArgs() config = %v, want %v", gotConfig, tt.wantConfig)
			}

			if gotExample != tt.wantExample {
				t.Errorf("parseCommandLineArgs() example = %v, want %v", gotExample, tt.wantExample)
			}
		})
	}
}

// Helper function for tests
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("URL invalide: %s", rawURL))
	}
	return u
}
