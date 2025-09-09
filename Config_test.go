package main

import (
	"bytes"
	"net/url"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
	if _, err := os.Stat("proxy-config.yaml"); os.IsNotExist(err) {
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
			server := NewServer(tt.config)

			// Capture stdout
			var buf bytes.Buffer
			origStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Display configuration
			server.DisplayConfiguration("test-config.yaml")

			// Restore stdout and read output
			w.Close()
			os.Stdout = origStdout
			buf.ReadFrom(r)

			output := buf.String()

			// Basic checks
			if !strings.Contains(output, "hnProxy configuré") {
				t.Error("Output should contain 'hnProxy configuré'")
			}

			if !strings.Contains(output, "test-config.yaml") {
				t.Error("Output should contain config file name")
			}

			if tt.config.TLS != nil && tt.config.TLS.Enabled {
				if !strings.Contains(output, "HTTPS activé") {
					t.Error("Output should indicate HTTPS is enabled")
				}
			} else {
				if !strings.Contains(output, "Mode HTTP") {
					t.Error("Output should indicate HTTP mode")
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
