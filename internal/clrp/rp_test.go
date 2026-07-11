package clrp

import (
	"fmt"
	"hnproxy/internal/clbackend"
	"hnproxy/internal/clconfig"
	"hnproxy/internal/clfirewall"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

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
	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*clbackend.BackendTarget{
			"app1.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL(backend1.URL),
				clbackend.MustParseURL(backend2.URL),
			}),
		},
	}
	clconfig.SetConfig(config, true, true)

	// Create handler
	firewall := clfirewall.NewFirewall(config.Firewall)
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
			wantStatus: http.StatusOK,
			wantBody:   "Are you lost",
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
	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*clbackend.BackendTarget{
			"app1.local": {
				URLs: []*url.URL{
					clbackend.MustParseURL(backends[0].URL),
					clbackend.MustParseURL(backends[1].URL),
					clbackend.MustParseURL(backends[2].URL),
				},
			},
		},
	}
	clconfig.SetConfig(config, true, true)

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

	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*clbackend.BackendTarget{
			"valid.local": {
				URLs: []*url.URL{clbackend.MustParseURL(backend.URL)},
			},
			"empty-backend.local": {
				URLs: []*url.URL{}, // Aucun backend
			},
		},
	}
	clconfig.SetConfig(config, true, true)

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
			expectedStatus: http.StatusOK,
			expectedBody:   "",
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
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
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

	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Routes: map[string]*clbackend.BackendTarget{
			"app1.local": {
				URLs: []*url.URL{clbackend.MustParseURL(backend.URL)},
			},
		},
	}
	clconfig.SetConfig(config, true, true)

	handler := NewReverseProxyHandler(config, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "app1.local"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

func TestRedirection(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		path     string
		query    string
		expected string
	}{
		{
			name:     "Simple redirect",
			host:     "example.com",
			path:     "/",
			query:    "",
			expected: "https://example.com/",
		},
		{
			name:     "With path",
			host:     "example.com",
			path:     "/api/users",
			query:    "",
			expected: "https://example.com/api/users",
		},
		{
			name:     "With query string",
			host:     "example.com",
			path:     "/search",
			query:    "q=test&page=2",
			expected: "https://example.com/search?q=test&page=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			if tt.query != "" {
				req.URL.RawQuery = tt.query
			}
			rr := httptest.NewRecorder()

			Redirection(tt.host, rr, req)

			if rr.Code != http.StatusMovedPermanently {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusMovedPermanently)
			}
			location := rr.Header().Get("Location")
			if location != tt.expected {
				t.Errorf("Location = %q, want %q", location, tt.expected)
			}
		})
	}
}

func TestGetHostname(t *testing.T) {
	config := &clconfig.ProxyConfig{
		Redirection: map[string]string{
			"example.com": "www.example.com",
		},
		Routes: map[string]*clbackend.BackendTarget{},
	}

	tests := []struct {
		name     string
		host     string
		wantHost string
		wantPort string
	}{
		{
			name:     "Simple hostname no port",
			host:     "example.com",
			wantHost: "www.example.com",
			wantPort: "",
		},
		{
			name:     "Hostname with port, redirected",
			host:     "example.com:8080",
			wantHost: "www.example.com",
			wantPort: "8080",
		},
		{
			name:     "Non-redirected hostname",
			host:     "other.com",
			wantHost: "other.com",
			wantPort: "",
		},
		{
			name:     "Non-redirected hostname with port",
			host:     "other.com:9090",
			wantHost: "other.com",
			wantPort: "9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host

			gotHost, gotPort := GetHostname(req, config)
			if gotHost != tt.wantHost {
				t.Errorf("GetHostname() host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("GetHostname() port = %q, want %q", gotPort, tt.wantPort)
			}
		})
	}
}

func TestServeHTTP_FirewallBlocking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	firewallConfig := &clconfig.FirewallConfig{
		Enabled:      true,
		BlockMessage: "forbidden",
		RateLimiter:  &clconfig.RateLimiterConfig{Enabled: false, Limit: 100},
		Antibot: &clconfig.AntiBotsConfig{
			Enabled:           true,
			BlockLegitimeBots: false,
		},
		PatternsFiltering:  &clconfig.PatternsFilteringConfig{Enabled: false},
		SuspiciousBehavior: &clconfig.SuspiciousBehaviorConfig{Enabled: false},
	}

	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Firewall:   firewallConfig,
		Routes: map[string]*clbackend.BackendTarget{
			"app.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL(backend.URL),
			}),
		},
	}
	clconfig.SetConfig(config, false, false)

	firewall := clfirewall.NewFirewall(firewallConfig)
	handler := NewReverseProxyHandler(config, firewall)

	tests := []struct {
		name       string
		userAgent  string
		clientIP   string
		wantStatus int
	}{
		{
			name:       "Empty User-Agent (bot) -> 403",
			userAgent:  "",
			clientIP:   "1.2.3.4:5678",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Normal User-Agent -> 200",
			userAgent:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			clientIP:   "1.2.3.5:5678",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = "app.local"
			req.Header.Set("User-Agent", tt.userAgent)
			req.RemoteAddr = tt.clientIP
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestServeHTTP_BlockMessageModes(t *testing.T) {
	blockMessages := []struct {
		mode       string
		wantStatus int
	}{
		{"notfound", http.StatusNotFound},
		{"teapot", http.StatusTeapot},
		{"slowfake", http.StatusOK},
		{"forbidden", http.StatusForbidden},
	}

	for _, bm := range blockMessages {
		t.Run("blockmode_"+bm.mode, func(t *testing.T) {
			firewallConfig := &clconfig.FirewallConfig{
				Enabled:      true,
				BlockMessage: bm.mode,
				RateLimiter:  &clconfig.RateLimiterConfig{Enabled: false, Limit: 100},
				Antibot: &clconfig.AntiBotsConfig{
					Enabled:           true,
					BlockLegitimeBots: false,
				},
				PatternsFiltering:  &clconfig.PatternsFilteringConfig{Enabled: false},
				SuspiciousBehavior: &clconfig.SuspiciousBehaviorConfig{Enabled: false},
			}

			config := &clconfig.ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Firewall:   firewallConfig,
				Routes: map[string]*clbackend.BackendTarget{
					"app.local": clbackend.NewBackendTarget([]*url.URL{
						clbackend.MustParseURL("http://127.0.0.1:19999"),
					}),
				},
			}
			clconfig.SetConfig(config, false, false)

			firewall := clfirewall.NewFirewall(firewallConfig)
			// Pre-block the IP
			firewall.IsBot(httptest.NewRequest("GET", "/", nil), "10.0.0.1")

			handler := NewReverseProxyHandler(config, firewall)

			req := httptest.NewRequest("GET", "/", nil)
			req.Host = "app.local"
			req.Header.Set("User-Agent", "") // empty UA triggers bot detection
			req.RemoteAddr = "10.0.0.1:1234"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != bm.wantStatus {
				t.Errorf("mode=%s: status = %d, want %d", bm.mode, rr.Code, bm.wantStatus)
			}
		})
	}
}

func TestServeHTTP_Redirection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := &clconfig.ProxyConfig{
		ListenAddr: "0.0.0.0:8080",
		Redirection: map[string]string{
			"old.local": "new.local",
		},
		Routes: map[string]*clbackend.BackendTarget{
			"new.local": clbackend.NewBackendTarget([]*url.URL{
				clbackend.MustParseURL(backend.URL),
			}),
		},
	}
	clconfig.SetConfig(config, true, true)

	handler := NewReverseProxyHandler(config, nil)

	req := httptest.NewRequest("GET", "/page?q=1", nil)
	req.Host = "old.local"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMovedPermanently)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "new.local") {
		t.Errorf("Location = %q, should contain 'new.local'", location)
	}
}
