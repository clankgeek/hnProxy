package main

import (
	"fmt"
	"net/url"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"
)

// Configuration YAML
type Config struct {
	Listen string           `yaml:"listen"`
	TLS    *TLSConfig       `yaml:"tls,omitempty"`
	Routes map[string]Route `yaml:"routes"`
}

type TLSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ACME         *ACME  `yaml:"acme,omitempty"`
	CertFile     string `yaml:"cert_file,omitempty"`
	KeyFile      string `yaml:"key_file,omitempty"`
	RedirectHTTP bool   `yaml:"redirect_http"`
}

type ACME struct {
	Email        string   `yaml:"email"`
	Domains      []string `yaml:"domains"`
	CacheDir     string   `yaml:"cache_dir"`
	DirectoryURL string   `yaml:"directory_url,omitempty"` // Pour staging
}

type Route struct {
	Backends []string `yaml:"backends"`
}

// Configuration interne du reverse proxy
type ProxyConfig struct {
	ListenAddr string
	TLS        *TLSConfig
	Routes     map[string]*BackendTarget
}

// handleExampleCreation creates an example configuration file
func handleExampleCreation() error {
	filename := "proxy-config.yaml"
	if err := createExampleConfig(filename); err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("✅ Fichier exemple créé: %s\n", filename)
	fmt.Println("⚠️  N'oubliez pas de :")
	fmt.Println("   - Modifier l'email ACME")
	fmt.Println("   - Changer les domaines")
	fmt.Println("   - Retirer 'directory_url' pour utiliser Let's Encrypt production")
	return nil
}

// Configurer ACME autocert
func setupACME(tlsConfig *TLSConfig) (*autocert.Manager, error) {
	if tlsConfig.ACME == nil {
		return nil, fmt.Errorf("configuration ACME manquante")
	}

	// Créer le répertoire de cache s'il n'existe pas
	if tlsConfig.ACME.CacheDir != "" {
		if err := os.MkdirAll(tlsConfig.ACME.CacheDir, 0700); err != nil {
			return nil, fmt.Errorf("impossible de créer le répertoire cache: %v", err)
		}
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      tlsConfig.ACME.Email,
		HostPolicy: autocert.HostWhitelist(tlsConfig.ACME.Domains...),
		Cache:      autocert.DirCache(tlsConfig.ACME.CacheDir),
	}

	// Utiliser Let's Encrypt staging si spécifié
	if tlsConfig.ACME.DirectoryURL != "" {
		client := &acme.Client{
			DirectoryURL: tlsConfig.ACME.DirectoryURL,
		}
		manager.Client = client
	}

	return manager, nil
}

// Créer un fichier de configuration exemple
func createExampleConfig(filename string) error {
	example := Config{
		Listen: "0.0.0.0:8080",
		TLS: &TLSConfig{
			Enabled: true,
			ACME: &ACME{
				Email:        "admin@example.com",
				Domains:      []string{"app1.example.com", "app2.example.com", "api.example.com"},
				CacheDir:     "./certs",
				DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", // Staging pour les tests
			},
			RedirectHTTP: true,
		},
		Routes: map[string]Route{
			"app1.example.com": {
				Backends: []string{
					"http://127.0.0.1:3001",
					"http://127.0.0.1:3002",
				},
			},
			"app2.example.com": {
				Backends: []string{
					"http://127.0.0.1:4001",
				},
			},
			"api.example.com": {
				Backends: []string{
					"http://127.0.0.1:5001",
					"http://127.0.0.1:5002",
					"http://127.0.0.1:5003",
				},
			},
		},
	}

	data, err := yaml.Marshal(example)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// loadAndValidateConfig loads and validates the configuration
func loadAndValidateConfig(configFile string) (*ProxyConfig, error) {
	// Charger la configuration YAML
	yamlConfig, err := loadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("erreur chargement config: %v", err)
	}

	// Convertir en config interne
	proxyConfig, err := convertConfig(yamlConfig)
	if err != nil {
		return nil, fmt.Errorf("erreur conversion config: %v", err)
	}

	// Validation
	if err := ValidateConfig(proxyConfig); err != nil {
		return nil, fmt.Errorf("configuration invalide: %v", err)
	}

	return proxyConfig, nil
}

// ValidateConfig validates the configuration
func ValidateConfig(config *ProxyConfig) error {
	if config.ListenAddr == "" {
		return fmt.Errorf("adresse d'écoute non définie")
	}

	if len(config.Routes) == 0 {
		return fmt.Errorf("aucune route définie")
	}

	// Validate TLS config if enabled
	if config.TLS != nil && config.TLS.Enabled {
		if config.TLS.ACME != nil {
			if config.TLS.ACME.Email == "" {
				return fmt.Errorf("email ACME requis")
			}
			if len(config.TLS.ACME.Domains) == 0 {
				return fmt.Errorf("domaines ACME requis")
			}
		} else if config.TLS.CertFile == "" || config.TLS.KeyFile == "" {
			return fmt.Errorf("certificats TLS manquants")
		}
	}

	return nil
}

// Convertir la config YAML en config interne
func convertConfig(yamlConfig *Config) (*ProxyConfig, error) {
	proxyConfig := &ProxyConfig{
		ListenAddr: yamlConfig.Listen,
		TLS:        yamlConfig.TLS,
		Routes:     make(map[string]*BackendTarget),
	}

	for hostname, route := range yamlConfig.Routes {
		urls := make([]*url.URL, 0, len(route.Backends))

		for _, backend := range route.Backends {
			u, err := url.Parse(backend)
			if err != nil {
				return nil, fmt.Errorf("URL invalide pour %s: %s (%v)", hostname, backend, err)
			}

			// Validation supplémentaire pour s'assurer que l'URL est valide pour un backend
			if u.Scheme != "http" && u.Scheme != "https" {
				return nil, fmt.Errorf("scheme invalide pour %s: %s (seuls http/https sont supportés)", hostname, backend)
			}
			if u.Host == "" {
				return nil, fmt.Errorf("host manquant pour %s: %s", hostname, backend)
			}

			urls = append(urls, u)
		}

		proxyConfig.Routes[hostname] = NewBackendTarget(urls)
	}

	return proxyConfig, nil
}

// Charger la configuration YAML
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire le fichier %s: %v", filename, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("erreur de parsing YAML: %v", err)
	}

	return &config, nil
}
