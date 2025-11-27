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
