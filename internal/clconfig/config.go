package clconfig

import (
	"fmt"
	"hnproxy/internal/clbackend"
	"log/syslog"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// Configuration interne du reverse proxy
type ProxyConfig struct {
	ListenAddr  string
	Firewall    *FirewallConfig
	TLS         *TLSConfig
	Redirection map[string]string
	Routes      map[string]*clbackend.BackendTarget
	Logger      LoggerConfig
	Production  bool
}

// Configuration YAML
type Config struct {
	Production  bool              `yaml:"production"`
	Listen      string            `yaml:"listen"`
	Firewall    *FirewallConfig   `yaml:"firewall"`
	TLS         *TLSConfig        `yaml:"tls,omitempty"`
	Redirection map[string]string `yaml:"redirection,omitempty"`
	Routes      map[string]Route  `yaml:"routes"`
	Logger      LoggerConfig      `yaml:"logger"`
}

type FirewallConfig struct {
	Enabled              bool                        `yaml:"enabled"`
	Redis                *RedisConfig                `yaml:"redis,omitempty"`
	BlockMessage         string                      `yaml:"blockmessage"`
	RateLimiter          *RateLimiterConfig          `yaml:"ratelimiter"`
	Antibot              *AntiBotsConfig             `yaml:"antibot"`
	PatternsFiltering    *PatternsFilteringConfig    `yaml:"patternsfiltering"`
	SuspiciousBehavior   *SuspiciousBehaviorConfig   `yaml:"suspiciousbehavior"`
	GeolocationFiltering *GeolocationFilteringConfig `yaml:"geolocationfiltering,omitempty"`
}

type RedisConfig struct {
	Addr string `yaml:"addr"`
	Db   int    `yaml:"db"`
}

type GeolocationFilteringConfig struct {
	Enabled               bool     `yaml:"enabled"`
	DatabasePath          string   `yaml:"dbpath,omitempty"`
	NotAllowedActionBlock bool     `yaml:"notallowedactionblock,omitempty"`
	AllowedCountries      []string `yaml:"allowedCountries,omitempty"`
	DisallowedCountries   []string `yaml:"disallowedCountries,omitempty"`
}

type PatternsFilteringConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SuspiciousBehaviorConfig struct {
	Enabled          bool `yaml:"enabled"`
	WordpressRemover bool `yaml:"wordpressremover"`
}

type RateLimiterConfig struct {
	Enabled bool `yaml:"enabled"`
	Limit   int  `yaml:"limit"`
}

type AntiBotsConfig struct {
	Enabled           bool `yaml:"enabled"`
	BlockLegitimeBots bool `yaml:"blockLegitimeBots"`
	BlockIABots       bool `yaml:"blockIABots"`
}

type TLSConfig struct {
	Enabled      bool        `yaml:"enabled"`
	RedirectHTTP bool        `yaml:"redirect_http"`
	ACME         *ACMEconfig `yaml:"acme"`
	CertFile     string      `yaml:"cert_file"`
	KeyFile      string      `yaml:"key_file"`
}

type ACMEconfig struct {
	Enabled      bool     `yaml:"enabled"`
	Email        string   `yaml:"email"`
	Domains      []string `yaml:"domains"`
	CacheDir     string   `yaml:"cache_dir"`
	DirectoryURL string   `yaml:"directory_url,omitempty"` // Pour staging
}

type Route struct {
	Backends []string `yaml:"backends"`
}

type LoggerConfig struct {
	Level  string             `yaml:"level"`
	File   LoggerFileConfig   `yaml:"file"`
	Syslog LoggerSyslogConfig `yaml:"syslog"`
}

type LoggerFileConfig struct {
	Enable     bool   `yaml:"enable"`
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAge     int    `yaml:"maxage"`
	Compress   bool   `yaml:"compress"`
}

type LoggerSyslogConfig struct {
	Enable   bool            `yaml:"enable"`
	Protocol string          `yaml:"protocol"`
	Address  string          `yaml:"address"`
	Tag      string          `yaml:"tag"`
	Priority syslog.Priority `yaml:"priority"`
}

// handleExampleCreation creates an example configuration file
func HandleExampleCreation(filename string) error {
	absolute := true
	if filename == "" {
		filename = "hnproxy.yaml"
		absolute = false
	}
	if err := CreateExampleConfig(filename, absolute); err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("Fichier exemple créé: %s\n", filename)
	fmt.Println("/!\\  N'oubliez pas de :")
	fmt.Println("   - Modifier l'email ACME")
	fmt.Println("   - Changer les domaines")
	fmt.Println("   - Retirer 'directory_url' pour utiliser Let's Encrypt production")
	return nil
}

// Créer un fichier de configuration exemple
func CreateExampleConfig(filename string, absolute bool) error {
	example := Config{
		Listen: "0.0.0.0:8080",
		Firewall: &FirewallConfig{
			Enabled:      true,
			Redis:        &RedisConfig{},
			BlockMessage: "forbidden",
			RateLimiter: &RateLimiterConfig{
				Enabled: false,
				Limit:   100,
			},
			Antibot: &AntiBotsConfig{
				Enabled:           true,
				BlockLegitimeBots: false,
				BlockIABots:       false,
			},
			PatternsFiltering: &PatternsFilteringConfig{
				Enabled: false,
			},
			SuspiciousBehavior: &SuspiciousBehaviorConfig{
				Enabled:          false,
				WordpressRemover: true,
			},
			GeolocationFiltering: &GeolocationFilteringConfig{
				Enabled: false,
			},
		},
		TLS: &TLSConfig{
			ACME: &ACMEconfig{},
		},
		Redirection: map[string]string{
			"example.com": "www.example.com",
		},
		Routes: map[string]Route{
			"www.example.com": {
				Backends: []string{
					"http://127.0.0.1:8000",
				},
			},
		},
		Logger: LoggerConfig{
			Level: "info",
			File: LoggerFileConfig{
				Enable: false,
			},
			Syslog: LoggerSyslogConfig{
				Enable: false,
			},
		},
	}
	if absolute {
		example.Production = true
		example.Listen = "0.0.0.0:443"
		example.TLS = &TLSConfig{
			Enabled:      true,
			RedirectHTTP: true,
			ACME: &ACMEconfig{
				Enabled:      true,
				Email:        "admin@example.com",
				Domains:      []string{"app1.example.com"},
				CacheDir:     "/var/lib/hnproxy/certs",
				DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", // Staging pour les tests
			},
		}
		example.Logger.File = LoggerFileConfig{
			Enable:     true,
			Path:       "/var/log/hnproxy/hnproxy.log",
			MaxSize:    100,
			MaxBackups: 30,
			MaxAge:     7,
			Compress:   true,
		}
	}

	data, err := yaml.Marshal(example)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// loadAndValidateConfig loads and validates the configuration
func LoadAndValidateConfig(configFile string) (*ProxyConfig, error) {
	// Charger la configuration YAML
	yamlConfig, err := LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("erreur chargement config: %v", err)
	}

	// Convertir en config interne
	proxyConfig, err := ConvertConfig(yamlConfig)
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
	if config.TLS.Enabled {
		if config.TLS.ACME.Enabled {
			if config.TLS.ACME.Email == "" {
				return fmt.Errorf("email ACME requis")
			}
			if len(config.TLS.ACME.Domains) == 0 {
				return fmt.Errorf("domaines ACME requis")
			}
		} else if config.TLS.CertFile == "" || config.TLS.KeyFile == "" {
			return fmt.Errorf("certificats TLS manquants (cert_file ou key_file)")
		}
	}
	return nil
}

// Convertir la config YAML en config interne
func ConvertConfig(yamlConfig *Config) (*ProxyConfig, error) {
	proxyConfig := &ProxyConfig{
		ListenAddr:  yamlConfig.Listen,
		Firewall:    yamlConfig.Firewall,
		TLS:         yamlConfig.TLS,
		Redirection: yamlConfig.Redirection,
		Routes:      make(map[string]*clbackend.BackendTarget),
		Logger:      yamlConfig.Logger,
		Production:  yamlConfig.Production,
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

		proxyConfig.Routes[hostname] = clbackend.NewBackendTarget(urls)
	}

	return proxyConfig, nil
}

func NewConfig() *Config {
	return &Config{
		Firewall: &FirewallConfig{
			Redis:                &RedisConfig{},
			RateLimiter:          &RateLimiterConfig{},
			Antibot:              &AntiBotsConfig{},
			PatternsFiltering:    &PatternsFilteringConfig{},
			SuspiciousBehavior:   &SuspiciousBehaviorConfig{},
			GeolocationFiltering: &GeolocationFilteringConfig{},
		},
		TLS: &TLSConfig{
			ACME: &ACMEconfig{},
		},
	}
}

func SetConfig(config *ProxyConfig, firewall bool, tls bool) {
	if firewall {
		config.Firewall = &FirewallConfig{
			Redis:                &RedisConfig{},
			RateLimiter:          &RateLimiterConfig{},
			Antibot:              &AntiBotsConfig{},
			PatternsFiltering:    &PatternsFilteringConfig{},
			SuspiciousBehavior:   &SuspiciousBehaviorConfig{},
			GeolocationFiltering: &GeolocationFilteringConfig{},
		}
	}
	if tls {
		config.TLS = &TLSConfig{
			ACME: &ACMEconfig{},
		}
	}
}

// Charger la configuration YAML
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire le fichier %s: %v", filename, err)
	}

	config := NewConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("erreur de parsing YAML: %v", err)
	}
	return config, nil
}
