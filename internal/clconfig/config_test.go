package clconfig

import (
	"hnproxy/internal/clbackend"
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

	err = HandleExampleCreation("")
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

			_, err = LoadAndValidateConfig(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadAndValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
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
			_, err = LoadConfig(tmpFile.Name())
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
			_, err := ConvertConfig(tt.config)
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
				Routes: map[string]*clbackend.BackendTarget{
					"app1.local": {
						URLs: []*url.URL{clbackend.MustParseURL("http://127.0.0.1:3001")},
					},
				},
				TLS: &TLSConfig{ACME: &ACMEconfig{}},
			},
			wantErr: false,
		},
		{
			name: "Missing listen address",
			config: &ProxyConfig{
				Routes: map[string]*clbackend.BackendTarget{
					"app1.local": {
						URLs: []*url.URL{clbackend.MustParseURL("http://127.0.0.1:3001")},
					},
				},
				TLS: &TLSConfig{ACME: &ACMEconfig{}},
			},
			wantErr: true,
			errMsg:  "adresse d'écoute non définie",
		},
		{
			name: "No routes",
			config: &ProxyConfig{
				ListenAddr: "0.0.0.0:8080",
				Routes:     map[string]*clbackend.BackendTarget{},
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
					ACME:    &ACMEconfig{},
				},
				Routes: map[string]*clbackend.BackendTarget{
					"app1.local": {
						URLs: []*url.URL{clbackend.MustParseURL("http://127.0.0.1:3001")},
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
					ACME: &ACMEconfig{
						Enabled: true,
						Email:   "test@example.com",
						Domains: []string{"app1.example.com"},
					},
				},
				Routes: map[string]*clbackend.BackendTarget{
					"app1.example.com": {
						URLs: []*url.URL{clbackend.MustParseURL("http://127.0.0.1:3001")},
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
					ACME: &ACMEconfig{
						Enabled: true,
						Domains: []string{"app1.example.com"},
					},
				},
				Routes: map[string]*clbackend.BackendTarget{
					"app1.example.com": {
						URLs: []*url.URL{clbackend.MustParseURL("http://127.0.0.1:3001")},
					},
				},
			},
			wantErr: true,
			errMsg:  "email ACME requis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetConfig(tt.config, true, false)
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

	err = CreateExampleConfig(tmpFile.Name(), false)
	if err != nil {
		t.Fatalf("createExampleConfig() failed: %v", err)
	}

	// Read and validate the created config
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read created config: %v", err)
	}

	config := NewConfig()

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

	if config.TLS.Enabled {
		t.Error("Generated config should not have TLS enabled")
	}
}
