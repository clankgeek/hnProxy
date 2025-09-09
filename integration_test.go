//go:build integration
// +build integration

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestIntegrationFullProxy tests the complete proxy flow
func TestIntegrationFullProxy(t *testing.T) {
	// Create multiple backend servers
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Backend-ID", "backend1")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Response from backend1 - Path: %s", r.URL.Path)
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Backend-ID", "backend2")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Response from backend2 - Path: %s", r.URL.Path)
	}))
	defer backend2.Close()

	// Create config file
	configContent := fmt.Sprintf(`
listen: "127.0.0.1:0"
routes:
  app1.local:
    backends:
      - "%s"
      - "%s"
  app2.local:
    backends:
      - "%s"
`, backend1.URL, backend2.URL, backend1.URL)

	configFile, err := os.CreateTemp("", "integration-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Load and convert config
	yamlConfig, err := loadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	if err := ValidateConfig(proxyConfig); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Create and start proxy server
	handler := NewReverseProxyHandler(proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Test cases
	tests := []struct {
		name         string
		host         string
		path         string
		wantStatus   int
		wantBackends []string // Possible backend IDs
	}{
		{
			name:         "App1 root path",
			host:         "app1.local",
			path:         "/",
			wantStatus:   http.StatusOK,
			wantBackends: []string{"backend1", "backend2"},
		},
		{
			name:         "App1 with path",
			host:         "app1.local",
			path:         "/api/users",
			wantStatus:   http.StatusOK,
			wantBackends: []string{"backend1", "backend2"},
		},
		{
			name:         "App2 single backend",
			host:         "app2.local",
			path:         "/health",
			wantStatus:   http.StatusOK,
			wantBackends: []string{"backend1"},
		},
		{
			name:       "Unknown host",
			host:       "unknown.local",
			path:       "/",
			wantStatus: http.StatusNotFound,
		},
	}

	// Run tests
	client := &http.Client{Timeout: 5 * time.Second}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", proxyServer.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Host = tt.host

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if len(tt.wantBackends) > 0 {
				backendID := resp.Header.Get("Backend-ID")
				found := false
				for _, expectedBackend := range tt.wantBackends {
					if backendID == expectedBackend {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Backend-ID = %s, want one of %v", backendID, tt.wantBackends)
				}
			}
		})
	}
}

// TestIntegrationLoadBalancing tests round-robin load balancing
func TestIntegrationLoadBalancing(t *testing.T) {
	const numBackends = 3
	const numRequests = 9 // 3 requests per backend

	// Create backend servers
	backends := make([]*httptest.Server, numBackends)
	for i := 0; i < numBackends; i++ {
		id := fmt.Sprintf("backend%d", i)
		backends[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Backend-ID", id)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(id))
		}))
		defer backends[i].Close()
	}

	// Create config
	configContent := `listen: "127.0.0.1:0"
routes:
  test.local:
    backends:`
	for _, backend := range backends {
		configContent += fmt.Sprintf("\n      - \"%s\"", backend.URL)
	}

	configFile, err := os.CreateTemp("", "lb-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Setup proxy
	yamlConfig, err := loadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	handler := NewReverseProxyHandler(proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Make requests and count responses
	client := &http.Client{Timeout: 5 * time.Second}
	backendCounts := make(map[string]int)

	for i := 0; i < numRequests; i++ {
		req, err := http.NewRequest("GET", proxyServer.URL, nil)
		if err != nil {
			t.Fatalf("Failed to create request %d: %v", i, err)
		}
		req.Host = "test.local"

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d status = %d", i, resp.StatusCode)
		}

		backendID := resp.Header.Get("Backend-ID")
		backendCounts[backendID]++
		resp.Body.Close()
	}

	// Verify load balancing
	expectedCount := numRequests / numBackends
	for i := 0; i < numBackends; i++ {
		backendID := fmt.Sprintf("backend%d", i)
		if count := backendCounts[backendID]; count != expectedCount {
			t.Errorf("Backend %s received %d requests, want %d", backendID, count, expectedCount)
		}
	}
}

// TestIntegrationConcurrentRequests tests concurrent request handling
func TestIntegrationConcurrentRequests(t *testing.T) {
	// Create backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create config
	configContent := fmt.Sprintf(`
listen: "127.0.0.1:0"
routes:
  concurrent.local:
    backends:
      - "%s"
`, backend.URL)

	configFile, err := os.CreateTemp("", "concurrent-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Setup proxy
	yamlConfig, err := loadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	handler := NewReverseProxyHandler(proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Make concurrent requests
	const numConcurrent = 50
	results := make(chan error, numConcurrent)
	client := &http.Client{Timeout: 30 * time.Second}

	start := time.Now()

	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			req, err := http.NewRequest("GET", proxyServer.URL, nil)
			if err != nil {
				results <- fmt.Errorf("goroutine %d: failed to create request: %v", id, err)
				return
			}
			req.Host = "concurrent.local"

			resp, err := client.Do(req)
			if err != nil {
				results <- fmt.Errorf("goroutine %d: request failed: %v", id, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				results <- fmt.Errorf("goroutine %d: status = %d", id, resp.StatusCode)
				return
			}

			results <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numConcurrent; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}

	elapsed := time.Since(start)
	t.Logf("Handled %d concurrent requests in %v", numConcurrent, elapsed)

	// Should complete in reasonable time (much less than sequential)
	maxExpectedTime := time.Duration(numConcurrent/2) * 10 * time.Millisecond
	if elapsed > maxExpectedTime {
		t.Errorf("Concurrent requests took too long: %v, expected < %v", elapsed, maxExpectedTime)
	}
}

// TestIntegrationProxyHeaders tests forwarded headers
func TestIntegrationProxyHeaders(t *testing.T) {
	// Create backend that checks headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{
			"X-Forwarded-Proto": r.Header.Get("X-Forwarded-Proto"),
			"X-Forwarded-Host":  r.Header.Get("X-Forwarded-Host"),
			"X-Forwarded-For":   r.Header.Get("X-Forwarded-For"),
		}

		for key, value := range headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Create config
	configContent := fmt.Sprintf(`
listen: "127.0.0.1:0"
routes:
  headers.local:
    backends:
      - "%s"
`, backend.URL)

	configFile, err := os.CreateTemp("", "headers-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Setup proxy
	yamlConfig, err := loadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	handler := NewReverseProxyHandler(proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Make request
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", proxyServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Host = "headers.local"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check forwarded headers
	if proto := resp.Header.Get("X-Forwarded-Proto"); proto != "http" {
		t.Errorf("X-Forwarded-Proto = %s, want http", proto)
	}

	if host := resp.Header.Get("X-Forwarded-Host"); host != "headers.local" {
		t.Errorf("X-Forwarded-Host = %s, want headers.local", host)
	}

	if forwardedFor := resp.Header.Get("X-Forwarded-For"); forwardedFor == "" {
		t.Error("X-Forwarded-For header is missing")
	}
}

// TestIntegrationErrorHandling tests error scenarios
func TestIntegrationErrorHandling(t *testing.T) {
	// Suppress log output during tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	// Create config with non-existent backend
	configContent := `
listen: "127.0.0.1:0"
routes:
  error.local:
    backends:
      - "http://127.0.0.1:99999"  # Non-existent backend
`

	configFile, err := os.CreateTemp("", "error-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Setup proxy
	yamlConfig, err := loadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	handler := NewReverseProxyHandler(proxyConfig)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Make request to trigger backend error
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", proxyServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Host = "error.local"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should return 502 Bad Gateway for backend connection error
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}
