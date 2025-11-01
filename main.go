package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

const VERSION string = "1.1.0"

// Backend target avec load balancing simple
type BackendTarget struct {
	URLs    []*url.URL
	current int
	mu      sync.Mutex // Protection pour l'accès concurrent
}

// NewBackendTarget creates a new BackendTarget with proper initialization
func NewBackendTarget(urls []*url.URL) *BackendTarget {
	return &BackendTarget{
		URLs:    urls,
		current: 0,
		mu:      sync.Mutex{},
	}
}

// Round-robin simple pour sélectionner le prochain backend
func (bt *BackendTarget) NextURL() *url.URL {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if len(bt.URLs) == 0 {
		return nil
	}

	// Capture de l'index actuel et mise à jour
	currentIndex := bt.current
	bt.current = (bt.current + 1) % len(bt.URLs)

	return bt.URLs[currentIndex]
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
	Enabled            bool                      `yaml:"enabled"`
	BlockMessage       string                    `yaml:"blockmessage"`
	RateLimiter        *RateLimiterConfig        `yaml:"ratelimiter"`
	Antibot            *AntiBotsConfig           `yaml:"antibot"`
	PatternsFiltering  *PatternsFilteringConfig  `yaml:"patternsfiltering"`
	SuspiciousBehavior *SuspiciousBehaviorConfig `yaml:"suspiciousbehavior"`
}

type PatternsFilteringConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SuspiciousBehaviorConfig struct {
	Enabled bool `yaml:"enabled"`
}

type RateLimiterConfig struct {
	Enabled bool `yaml:"enabled"`
	Limit   int  `yaml:"limit"`
}

type AntiBotsConfig struct {
	Enabled           bool `yaml:"enabled"`
	BlockLegitimeBots bool `yaml:"blockLegitimeBots"`
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

// Configuration interne du reverse proxy
type ProxyConfig struct {
	ListenAddr  string
	Firewall    *FirewallConfig
	TLS         *TLSConfig
	Redirection map[string]string
	Routes      map[string]*BackendTarget
	Logger      LoggerConfig
	Production  bool
}

type LoggerConfig struct {
	Level  string             `yaml:"level"`
	File   loggerFileConfig   `yaml:"file"`
	Syslog loggerSyslogConfig `yaml:"syslog"`
}

type loggerFileConfig struct {
	Enable     bool   `yaml:"enable"`
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAge     int    `yaml:"maxage"`
	Compress   bool   `yaml:"compress"`
}

type loggerSyslogConfig struct {
	Enable   bool            `yaml:"enable"`
	Protocol string          `yaml:"protocol"`
	Address  string          `yaml:"address"`
	Tag      string          `yaml:"tag"`
	Priority syslog.Priority `yaml:"priority"`
}

// SyslogLevelWriter adapte syslog.Writer pour gérer les niveaux zerolog
type SyslogLevelWriter struct {
	writer *syslog.Writer
}

// InitLogger configure le logger global Zerolog
// Setup initialise le logger avec la configuration
func initLogger(cfg LoggerConfig, production bool) {
	// Définir le niveau de log
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configurer le format de temps
	zerolog.TimeFieldFormat = time.RFC3339

	var writers []io.Writer

	// Writer pour la console
	if !production {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
		writers = append(writers, consoleWriter)
	}

	// Writer pour le fichier si activé
	if cfg.File.Enable {
		fileWriter, err := setupFileWriter(cfg.File)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup file writer")
		}
		writers = append(writers, fileWriter)
	}

	// Writer syslog si activé
	if cfg.Syslog.Enable {
		syslogWriter, err := setupSyslogWriter(cfg.Syslog)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup syslog writer")
		}
		writers = append(writers, syslogWriter)
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	// Créer un multi-writer
	multi := io.MultiWriter(writers...)

	// Configurer le logger global
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	environnment := "developpement"
	if production {
		environnment = "production"
	}
	log.Info().
		Str("environment", environnment).
		Str("level", cfg.Level).
		Bool("log_to_file", cfg.File.Enable).
		Bool("log_to_syslog", cfg.Syslog.Enable).
		Msg("Logger initialisé")
}

// setupFileWriter configure le writer pour les fichiers
func setupFileWriter(cfg loggerFileConfig) (io.Writer, error) {
	// Créer le dossier si nécessaire
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	fileWriter := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	return fileWriter, nil
}

// setupSyslogWriter configure le writer pour syslog
func setupSyslogWriter(cfg loggerSyslogConfig) (io.Writer, error) {
	// Utiliser un tag par défaut si non spécifié
	tag := cfg.Tag
	if tag == "" {
		tag = "littleblog"
	}
	// Utiliser une priorité par défaut si non spécifiée
	priority := cfg.Priority
	if priority == 0 {
		priority = syslog.LOG_INFO | syslog.LOG_LOCAL0
	}

	var writer *syslog.Writer
	var err error

	// Connexion locale ou distante
	if cfg.Protocol == "" || cfg.Address == "" {
		// Connexion locale (Unix socket)
		writer, err = syslog.New(priority, tag)
	} else {
		// Connexion distante (TCP ou UDP)
		writer, err = syslog.Dial(cfg.Protocol, cfg.Address, priority, tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	// Wrapper pour adapter syslog.Writer à io.Writer avec le bon niveau
	return &SyslogLevelWriter{writer: writer}, nil
}

// Write implémente io.Writer et route vers la bonne fonction syslog selon le niveau
func (w *SyslogLevelWriter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Parser le niveau depuis le JSON zerolog
	level := extractLevelFromJSON(msg)

	// Router vers la bonne méthode syslog selon le niveau
	switch level {
	case "debug":
		return len(p), w.writer.Debug(msg)
	case "info":
		return len(p), w.writer.Info(msg)
	case "warn", "warning":
		return len(p), w.writer.Warning(msg)
	case "error":
		return len(p), w.writer.Err(msg)
	case "fatal", "panic":
		return len(p), w.writer.Crit(msg)
	default:
		// Par défaut, utiliser Info
		return len(p), w.writer.Info(msg)
	}
}

// extractLevelFromJSON extrait le niveau de log d'un message JSON zerolog
// Format attendu: {"level":"info",...}
func extractLevelFromJSON(msg string) string {
	// Recherche simple du champ "level" dans le JSON
	// Format: "level":"xxx"
	startIdx := strings.Index(msg, `"level":"`)
	if startIdx == -1 {
		return ""
	}

	// Décaler après "level":"
	startIdx += 9

	// Trouver la fin (guillemet suivant)
	endIdx := strings.Index(msg[startIdx:], `"`)
	if endIdx == -1 {
		return ""
	}

	return msg[startIdx : startIdx+endIdx]
}

func parseLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// WithFields retourne un logger avec des champs prédéfinis
func WithFields(fields map[string]interface{}) zerolog.Logger {
	ctx := log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// WithRequestID retourne un logger avec un request ID
func WithRequestID(requestID string) zerolog.Logger {
	return log.With().Str("request_id", requestID).Logger()
}

// Debug logue un message de debug
func LogDebug(msg string) {
	log.Debug().Msg(msg)
}

// Info logue un message d'information
func LogInfo(msg string) {
	log.Info().Msg(msg)
}

// Info logue avec printf
func LogPrintf(format string, a ...any) {
	log.Info().Msg(fmt.Sprintf(format, a...))
}

// Warn logue un avertissement
func LogWarn(msg string) {
	log.Warn().Msg(msg)
}

// Error logue une erreur
func LogError(err error, msg string) {
	log.Error().Err(err).Msg(msg)
}

// Fatal logue une erreur fatale et arrête le programme
func LogFatal(err error, msg string) {
	log.Fatal().Err(err).Str("msg", msg)
}

// handleExampleCreation creates an example configuration file
func handleExampleCreation(filename string) error {
	absolute := true
	if filename == "" {
		filename = "hnproxy.yaml"
		absolute = false
	}
	if err := createExampleConfig(filename, absolute); err != nil {
		return fmt.Errorf("erreur création exemple: %v", err)
	}

	fmt.Printf("Fichier exemple créé: %s\n", filename)
	fmt.Println("/!\\  N'oubliez pas de :")
	fmt.Println("   - Modifier l'email ACME")
	fmt.Println("   - Changer les domaines")
	fmt.Println("   - Retirer 'directory_url' pour utiliser Let's Encrypt production")
	return nil
}

// Configurer ACME autocert
func setupACME(tlsConfig *TLSConfig, production bool) (*autocert.Manager, error) {
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

		if !production {
			client.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // Pebble case
					},
				},
			}
		}

		manager.Client = client
	}

	return manager, nil
}

// Créer un fichier de configuration exemple
func createExampleConfig(filename string, absolute bool) error {
	example := Config{
		Listen: "0.0.0.0:8080",
		Firewall: &FirewallConfig{
			Enabled:      true,
			BlockMessage: "forbidden",
			RateLimiter: &RateLimiterConfig{
				Enabled: false,
				Limit:   100,
			},
			Antibot: &AntiBotsConfig{
				Enabled:           true,
				BlockLegitimeBots: false,
			},
			PatternsFiltering: &PatternsFilteringConfig{
				Enabled: false,
			},
			SuspiciousBehavior: &SuspiciousBehaviorConfig{
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
			File: loggerFileConfig{
				Enable: false,
			},
			Syslog: loggerSyslogConfig{
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
		example.Logger.File = loggerFileConfig{
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
func convertConfig(yamlConfig *Config) (*ProxyConfig, error) {
	proxyConfig := &ProxyConfig{
		ListenAddr:  yamlConfig.Listen,
		Firewall:    yamlConfig.Firewall,
		TLS:         yamlConfig.TLS,
		Redirection: yamlConfig.Redirection,
		Routes:      make(map[string]*BackendTarget),
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

		proxyConfig.Routes[hostname] = NewBackendTarget(urls)
	}

	return proxyConfig, nil
}

func NewConfig() *Config {
	return &Config{
		Firewall: &FirewallConfig{
			RateLimiter:        &RateLimiterConfig{},
			Antibot:            &AntiBotsConfig{},
			PatternsFiltering:  &PatternsFilteringConfig{},
			SuspiciousBehavior: &SuspiciousBehaviorConfig{},
		},
		TLS: &TLSConfig{
			ACME: &ACMEconfig{},
		},
	}
}

// Charger la configuration YAML
func loadConfig(filename string) (*Config, error) {
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

type Server struct {
	config  *ProxyConfig
	handler *ReverseProxyHandler
}

// NewServer creates a new server instance
func NewServer(config *ProxyConfig) *Server {
	var firewall *Firewall
	if config.Firewall != nil && config.Firewall.Enabled {
		firewall = NewFirewall(config.Firewall)
		firewall.CleanupRoutine()
	}
	return &Server{
		config:  config,
		handler: NewReverseProxyHandler(config, firewall),
	}
}

// runServer starts the appropriate server based on configuration
func runServer(server *Server) error {
	if server.config.TLS.Enabled {
		return server.StartHTTPSServer()
	} else {
		return server.StartHTTPServer()
	}
}

// StartHTTPServer starts the HTTP-only server
func (s *Server) StartHTTPServer() error {
	LogPrintf("Serveur HTTP démarré sur %s", s.config.ListenAddr)
	return http.ListenAndServe(s.config.ListenAddr, s.handler)
}

// StartHTTPSServer starts the HTTPS server with optional HTTP redirect
func (s *Server) StartHTTPSServer() error {
	if !s.config.TLS.Enabled {
		return fmt.Errorf("TLS non configuré")
	}

	// Setup HTTPS server
	server, err := s.createHTTPSServer()
	if err != nil {
		return fmt.Errorf("erreur création serveur HTTPS: %v", err)
	}

	LogPrintf("Serveur HTTPS démarré sur %s", s.config.ListenAddr)

	// Start HTTP server for ACME challenges and redirects
	if s.config.TLS.ACME.Enabled {
		go s.startACMEHTTPServer()
		return server.ListenAndServeTLS("", "")
	}

	return server.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
}

// createHTTPSServer creates the HTTPS server with proper TLS config
func (s *Server) createHTTPSServer() (*http.Server, error) {
	var tlsConfig *tls.Config

	if s.config.TLS.ACME.Enabled {
		manager, err := setupACME(s.config.TLS, s.config.Production)
		if err != nil {
			return nil, fmt.Errorf("erreur configuration ACME: %v", err)
		}
		tlsConfig = manager.TLSConfig()
	}

	server := &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      s.handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return server, nil
}

func validateHostname(h string, config *ProxyConfig, handler *ReverseProxyHandler, r *http.Request) bool {
	if _, exists := config.Routes[h]; !exists {
		log.Debug().Msg(fmt.Sprintf("❌ Invalid hostname (redirection): source: %s, hostname: %s path: %s", handler.firewall.GetClientIP(r), h, r.URL.Path))
		return false
	}
	return true
}

func getHostname(r *http.Request, config *ProxyConfig) (string, string) {
	hostname, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostname = r.Host
		port = ""
	}
	if h, exists := config.Redirection[hostname]; exists {
		log.Debug().Msg(fmt.Sprintf("Redirection de domaine de %s vers %s", hostname, h))
		return h, port
	}
	return hostname, port
}

func redirection(hostname string, w http.ResponseWriter, r *http.Request) {
	target := "https://" + hostname + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// Handler pour rediriger HTTP vers HTTPS
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	host, port := getHostname(r, s.config)

	if !validateHostname(host, s.config, s.handler, r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	if port != "" {
		host = host + ":" + port
	}
	log.Debug().Msg(fmt.Sprintf("Redirection HTTP vers HTTPS %s", host))
	redirection(host, w, r)
}

// startACMEHTTPServer starts the HTTP server for ACME challenges and redirects
func (s *Server) startACMEHTTPServer() {
	manager, err := setupACME(s.config.TLS, s.config.Production)
	if err != nil {
		LogPrintf("❌ Erreur ACME HTTP server: %v", err)
		return
	}

	httpMux := http.NewServeMux()
	httpMux.Handle("/.well-known/acme-challenge/", manager.HTTPHandler(nil))

	if s.config.TLS.RedirectHTTP {
		httpMux.HandleFunc("/", s.redirect)
	} else {
		httpMux.Handle("/", s.handler)
	}

	LogPrintf("🌐 Serveur HTTP démarré sur 0.0.0.0:80 (ACME + %s)",
		map[bool]string{true: "redirection", false: "proxy"}[s.config.TLS.RedirectHTTP])

	if err := http.ListenAndServe("0.0.0.0:80", httpMux); err != nil {
		LogPrintf("❌ Erreur serveur HTTP: %v", err)
	}
}

// DisplayConfiguration shows the server configuration
func (s *Server) DisplayConfiguration(configFile string) {
	LogPrintf("hnProxy configuré")
	LogPrintf("Configuration: %s", configFile)

	firewall := false
	if s.config.Firewall.Enabled {
		withAntibot := s.config.Firewall.Antibot.Enabled
		withRateLimiter := s.config.Firewall.RateLimiter.Enabled
		withPatternFiltering := s.config.Firewall.PatternsFiltering.Enabled
		withSuspiciousBehavior := s.config.Firewall.SuspiciousBehavior.Enabled

		if withAntibot || withRateLimiter || withPatternFiltering || withSuspiciousBehavior {
			firewall = true
			LogPrintf("🛡️ Firewall activé")
			switch s.config.Firewall.BlockMessage {
			case "slowfake":
				LogPrintf("  • Block message mode : 200 slowfake")
			case "teapot":
				LogPrintf("  • Block message mode : 418 teapot")
			case "notfound":
				LogPrintf("  • Block message mode : 404 not found")
			default:
				LogPrintf("  • Block message mode : 403 forbidden")
			}
			if withRateLimiter {
				LogPrintf("  • Rate Limiter activé à %d requettes par minute", s.config.Firewall.RateLimiter.Limit)
			}
			if withAntibot {
				bot := "  • 🤖 Antibot activé "
				if s.config.Firewall.Antibot.BlockLegitimeBots {
					bot += "avec bloquage des bots légitimes"
				} else {
					bot += "sans bloquage des bots légitimes"
				}
				log.Info().Msg(bot)
			}
			if withPatternFiltering {
				LogPrintf("Filtrage par pattern activé")
			}
			if withSuspiciousBehavior {
				LogPrintf("Filtrage sur action suspecte activé")
			}
		}

	}
	if !firewall {
		LogPrintf("🛡️ Firewall désactivé")
	}

	if s.config.TLS.Enabled {
		LogPrintf("HTTPS activé")
		if s.config.TLS.ACME != nil {
			LogPrintf("ACME configuré pour: %v", s.config.TLS.ACME.Domains)
			LogPrintf("Email: %s", s.config.TLS.ACME.Email)
			LogPrintf("Cache: %s", s.config.TLS.ACME.CacheDir)
		} else {
			LogPrintf("Certificats: %s, %s", s.config.TLS.CertFile, s.config.TLS.KeyFile)
		}
	} else {
		LogPrintf("Mode HTTP")
	}

	if len(s.config.Redirection) > 0 {
		LogPrintf("🔀 Redirection activée")
		for source, destination := range s.config.Redirection {
			LogPrintf("  • %s -> %s", source, destination)
		}
	} else {
		LogPrintf("🔀 Redirection désactivée")
	}

	LogPrintf("🔀 Routes configurées:")
	protocol := "http"
	if s.config.TLS.Enabled {
		protocol = "https"
	}
	for hostname, target := range s.config.Routes {
		backends := make([]string, len(target.URLs))
		for i, u := range target.URLs {
			backends[i] = u.String()
		}
		LogPrintf("  • %s://%s -> %v", protocol, hostname, backends)
	}

	LogPrintf("Logger en level %s", s.config.Logger.Level)
	if s.config.Logger.File.Enable {
		LogPrintf("  Log en fichier activé")
		LogPrintf("  • Path %s", s.config.Logger.File.Path)
		LogPrintf("  • Max size %d", s.config.Logger.File.MaxSize)
		LogPrintf("  • Max age %d", s.config.Logger.File.MaxAge)
		LogPrintf("  • Max backup %d", s.config.Logger.File.MaxBackups)
		LogPrintf("  • Compression %v", s.config.Logger.File.Compress)
	} else {
		LogPrintf("  Log en fichier désactivé")
	}
	if s.config.Logger.Syslog.Enable {
		LogPrintf("  Log en syslog activé")
		LogPrintf("  • Protocol %s", s.config.Logger.Syslog.Protocol)
		LogPrintf("  • Address %s", s.config.Logger.Syslog.Address)
		LogPrintf("  • Tag %s", s.config.Logger.Syslog.Tag)
		LogPrintf("  • Priority %v", s.config.Logger.Syslog.Priority)
	} else {
		LogPrintf("  Log en syslog désactivé")
	}
}

// Reverse Proxy Handler
type ReverseProxyHandler struct {
	config   *ProxyConfig
	firewall *Firewall
}

func NewReverseProxyHandler(config *ProxyConfig, firewall *Firewall) *ReverseProxyHandler {
	return &ReverseProxyHandler{
		config:   config,
		firewall: firewall,
	}
}

func (rph *ReverseProxyHandler) Firewall(r *http.Request) error {
	if rph.config.Firewall.Enabled && rph.firewall != nil {
		clientIp := rph.firewall.GetClientIP(r)
		if rph.firewall.isIPBlocked(clientIp) {
			return fmt.Errorf("")
		}
		if rph.firewall.IsLimiter(r, clientIp) {
			return fmt.Errorf("🚫 Requette rejetée par le firewall, module ratelimiter")
		}
		if rph.firewall.IsBot(r, clientIp) {
			return fmt.Errorf("🚫 Requette rejetée par le firewall, module antibot")
		}
	}
	return nil
}

func (rph *ReverseProxyHandler) serveTeaPot(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusTeapot) // 418 I'm a teapot

	// Paramètres aléatoires pour la théière
	bodyWidth := 120 + rand.Intn(80)   // 120-200
	bodyHeight := 100 + rand.Intn(60)  // 100-160
	lidWidth := 60 + rand.Intn(40)     // 60-100
	spoutCurve := 580 + rand.Intn(60)  // courbure du bec
	handleCurve := 160 + rand.Intn(60) // courbure de l'anse

	// Couleurs aléatoires
	colors := []string{
		"#8B4513", // marron
		"#CD853F", // beige
		"#4A90E2", // bleu
		"#E74C3C", // rouge
		"#2ECC71", // vert
		"#9B59B6", // violet
		"#F39C12", // orange
	}
	mainColor := colors[rand.Intn(len(colors))]

	// Position et taille de la vapeur
	steamCount := 2 + rand.Intn(3) // 2-4 jets de vapeur

	svg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600" width="100%%" height="100%%" preserveAspectRatio="xMidYMid meet">
  <style>
    svg { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); }
    .teapot { fill: %s; stroke: #333; stroke-width: 2; }
    .shine { fill: white; opacity: 0.3; }
    .steam { fill: #E0E0E0; opacity: 0.7; }
  </style>
  
  <!-- Steam animation -->
  <g class="steam">`, mainColor)

	// Génération aléatoire des jets de vapeur
	for i := 0; i < steamCount; i++ {
		x := 350 + i*30 + rand.Intn(20)
		y := 150 + rand.Intn(20)
		rx := 10 + rand.Intn(10)
		ry := 20 + rand.Intn(15)
		dur := 2.5 + rand.Float64()

		svg += fmt.Sprintf(`
    <ellipse cx="%d" cy="%d" rx="%d" ry="%d">
      <animate attributeName="cy" values="%d;%d;%d" dur="%.1fs" repeatCount="indefinite"/>
      <animate attributeName="opacity" values="0.7;0.4;0" dur="%.1fs" repeatCount="indefinite"/>
    </ellipse>`, x, y, rx, ry, y, y-50, y-100, dur, dur)
	}

	svg += fmt.Sprintf(`
  </g>
  
  <!-- Teapot body -->
  <ellipse class="teapot" cx="400" cy="400" rx="%d" ry="%d"/>
  
  <!-- Teapot lid -->
  <ellipse class="teapot" cx="400" cy="280" rx="%d" ry="30"/>
  <rect class="teapot" x="%d" y="250" width="40" height="30" rx="5"/>
  <ellipse class="teapot" cx="400" cy="250" rx="20" ry="15"/>
  
  <!-- Spout -->
  <path class="teapot" d="M 550 350 Q %d 350 620 380 Q 630 400 620 420 Q %d 450 550 450 L 550 350 Z"/>
  
  <!-- Handle -->
  <path class="teapot" d="M 250 320 Q 200 320 %d 360 Q 170 400 %d 440 Q 200 480 250 480" 
        fill="none" stroke="#333" stroke-width="25" stroke-linecap="round"/>
  
  <!-- Shine effects -->
  <ellipse class="shine" cx="350" cy="360" rx="40" ry="60"/>
  <ellipse class="shine" cx="320" cy="320" rx="20" ry="30"/>
  
  <!-- Text -->
  <text x="400" y="550" font-family="Arial, sans-serif" font-size="24" fill="white" text-anchor="middle" font-weight="bold">
    418 - I'm a teapot! ☕
  </text>
</svg>`,
		bodyWidth, bodyHeight,
		lidWidth, 400-20,
		spoutCurve, spoutCurve,
		handleCurve, handleCurve)

	w.Write([]byte(svg))
}

func (rph *ReverseProxyHandler) serveSlowFake(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Textes Lorem Ipsum variés
	loremParagraphs := []string{
		"<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>",
		"<p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>",
		"<p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.</p>",
		"<p>Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>",
		"<p>Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium.</p>",
		"<p>Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores.</p>",
		"<p>Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit.</p>",
		"<p>At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti.</p>",
	}

	header := `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chargement...</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        p { line-height: 1.6; color: #666; }
    </style>
</head>
<body>
    <h1>Veuillez patienter...</h1>
`

	footer := `
    <footer style="margin-top: 50px; text-align: center; color: #999;">
        <p>&copy; 2025 - Tous droits réservés</p>
    </footer>
</body>
</html>`

	// Envoie le header
	w.Write([]byte(header))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	time.Sleep(200 * time.Millisecond)

	// Envoie les paragraphes un par un
	numParagraphs := 10 + rand.Intn(20)

	for i := 0; i < numParagraphs; i++ {
		paragraph := loremParagraphs[rand.Intn(len(loremParagraphs))]

		w.Write([]byte(paragraph + "\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Délai aléatoire entre 200ms et 800ms
		delay := 200 + rand.Intn(600)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	// Envoie le footer
	w.Write([]byte(footer))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (rph *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hostname := strings.Split(r.Host, ":")[0]

	host, port := getHostname(r, rph.config)
	if host != hostname {
		if port != "" {
			host = host + ":" + port
		}
		redirection(host, w, r)
		return
	}

	err := rph.Firewall(r)
	if err != nil {
		msg := err.Error()
		if msg != "" {
			log.Error().Msg(msg)
		}
		switch rph.firewall.config.BlockMessage {
		case "notfound":
			http.Error(w, "Page not found", http.StatusNotFound)
		case "slowfake":
			rph.serveSlowFake(w)
		case "teapot":
			rph.serveTeaPot(w)
		default:
			http.Error(w, "Access Denied", http.StatusForbidden)
		}
		return
	}

	// Chercher la route correspondante
	target, exists := rph.config.Routes[hostname]
	if !exists {
		log.Debug().Msg(fmt.Sprintf("❌ Invalid hostname: source: %s, hostname: %s", rph.firewall.GetClientIP(r), r.Host))
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	// Sélectionner le backend
	backendURL := target.NextURL()
	if backendURL == nil {
		log.Debug().Msg(fmt.Sprintf("❌ Aucun backend disponible pour %s", hostname))
		http.Error(w, "Aucun backend disponible", http.StatusServiceUnavailable)
		return
	}

	// Créer le reverse proxy pour cette requête
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host

			// Conserver les headers de cache
			// If-Modified-Since, If-None-Match, etc. sont déjà copiés par défaut

			if req.Header.Get("X-Forwarded-Proto") == "" {
				if req.TLS != nil {
					req.Header.Set("X-Forwarded-Proto", "https")
				} else {
					req.Header.Set("X-Forwarded-Proto", "http")
				}
			}
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second, // Important !
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Ignorer silencieusement les annulations client (comportement normal)
			if errors.Is(err, context.Canceled) {
				return
			}

			if errors.Is(err, context.DeadlineExceeded) {
				log.Error().Msg(fmt.Sprintf("⏱️  Timeout: %s -> %s", hostname, backendURL.String()))
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}

			log.Error().
				Err(err).
				Str("hostname", hostname).
				Str("backend", backendURL.String()).
				Str("path", r.URL.Path).
				Msg("Erreur proxy")
			http.Error(w, "Service temporairement indisponible", http.StatusBadGateway)
		},
	}

	protocol := "HTTP"
	if r.TLS != nil {
		protocol = "HTTPS"
	}
	log.Debug().Msg(fmt.Sprintf("🔀 [%s] %s%s -> %s", protocol, hostname, r.URL.Path, backendURL.String()))
	proxy.ServeHTTP(w, r)
}

// Firewall gère la détection et le blocage des bots
type Firewall struct {
	config *FirewallConfig

	// Liste des User-Agents de bots connus
	botUserAgents []string

	// Liste des IP bloquées
	blockedIPs map[string]time.Time
	mu         sync.RWMutex

	// Patterns suspects dans les User-Agents
	suspiciousPatterns []string

	// Liste des bots légitimes
	legitimateBots []string

	rateLimiter *RateLimiter
}

// RateLimiter pour limiter le nombre de requêtes par IP
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int           // Nombre max de requêtes
	window   time.Duration // Fenêtre de temps
}

// NewFirewall crée une nouvelle instance de Firewall
func NewFirewall(config *FirewallConfig) *Firewall {
	return &Firewall{
		config: config,
		botUserAgents: []string{
			// Bots de scraping courants
			"python-requests",
			"python-urllib",
			"go-http-client",
			"scrapy",
			"wget",
			"curl",
			"libwww-perl",
			"PHP",
			"java",
			"ruby",

			// Bots malveillants connus
			"masscan",
			"nmap",
			"nikto",
			"sqlmap",
			"havij",
			"acunetix",
			"Sogou",

			// Bots commerciaux
			"ahrefsbot",
			"semrushbot",
			"dotbot",
			"mj12bot",
			"blexbot",
			"yandexbot",
			"baiduspider",
			"petalbot",
			"aspiegelbot",
			"zoominfobot",
			"barkrowler",
			"dataforseobot",
		},
		legitimateBots: []string{
			// Moteurs de recherche majeurs
			"Google",
			"googlebot",
			"googlebotvideos",
			"googlebot-image",
			"googlebot-news",
			"bingbot",
			"slurp", // Yahoo
			"duckduckbot",

			// Réseaux sociaux
			"facebookexternalhit",
			"facebookcatalog",
			"twitterbot",
			"linkedinbot",
			"whatsapp",
			"telegram",
			"discordbot",
			"slackbot",

			// Services de monitoring et SEO légitimes
			"uptimerobot",
			"pingdom",
			"newrelic",
			"datadog",

			// Autres services légitimes
			"applebot", // Siri et Spotlight
			"pinterest",
			"quora",
			"redditbot",
		},
		suspiciousPatterns: []string{
			"bot",
			"crawler",
			"spider",
			"scraper",
			"scan",
			"hack",
			"exploit",
			"fetch",
			"archiver",
			"analyzer",
			"monitor",
			"aggregator",
		},
		blockedIPs: make(map[string]time.Time),
		rateLimiter: &RateLimiter{
			requests: make(map[string][]time.Time),
			limit:    100,         // 100 requêtes
			window:   time.Minute, // par minute
		},
	}
}
func (bd *Firewall) IsLimiter(r *http.Request, clientIP string) bool {
	if bd.config.RateLimiter.Enabled && !bd.rateLimiter.Allow(clientIP) {
		log.Warn().Msg(fmt.Sprintf("🛡️	Rate limit dépassé pour %s", clientIP))
		bd.blockIP(clientIP, 15*time.Minute)
		return true
	}
	return false
}

// IsBot vérifie si la requête provient d'un bot
func (bd *Firewall) IsBot(r *http.Request, clientIP string) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	log.Debug().Msg(fmt.Sprintf("🤖 User Agent est : %s", userAgent))

	if bd.config.Antibot.Enabled {
		// Vérifier les bots légitimes SI on veut les bloquer
		if bd.config.Antibot.BlockLegitimeBots {
			for _, bot := range bd.legitimateBots {
				if strings.Contains(userAgent, bot) {
					log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot légitime bloqué: %s depuis %s", bot, clientIP))
					// Blocage plus court pour les bots légitimes (ils reviendront)
					bd.blockIP(clientIP, 30*time.Minute)
					return true
				}
			}
		}

		// Vérifier le User-Agent vide (suspect)
		if userAgent == "" {
			log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot détecté: User-Agent vide depuis %s", clientIP))
			bd.blockIP(clientIP, 1*time.Hour)
			return true
		}

		// Vérifier les User-Agents de bots connus (malveillants)
		for _, botUA := range bd.botUserAgents {
			if strings.Contains(userAgent, botUA) {
				log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot malveillant détecté: %s depuis %s", botUA, clientIP))
				bd.blockIP(clientIP, 24*time.Hour)
				return true
			}
		}
	}

	// Vérifier les patterns suspects
	if bd.config.PatternsFiltering.Enabled {
		for _, pattern := range bd.suspiciousPatterns {
			if strings.Contains(userAgent, pattern) {
				// Si on ne bloque PAS les bots légitimes, vérifier si c'en est un
				if !bd.config.Antibot.BlockLegitimeBots && bd.isLegitimateBot(userAgent) {
					// C'est un bot légitime et on ne les bloque pas
					log.Debug().Msg(fmt.Sprintf("Bot légitime autorisé: %s depuis %s", userAgent, clientIP))
					continue
				}
				// Sinon, c'est suspect et on bloque
				log.Warn().Msg(fmt.Sprintf("🛡️ Pattern suspect détecté: %s dans %s depuis %s", pattern, userAgent, clientIP))
				bd.blockIP(clientIP, 6*time.Hour)
				return true
			}
		}
	}

	// Vérifications additionnelles
	if bd.config.SuspiciousBehavior.Enabled && bd.hasSuspiciousBehavior(r) {
		log.Warn().Msg(fmt.Sprintf("🛡️🤖 Comportement suspect détecté depuis %s", clientIP))
		bd.blockIP(clientIP, 30*time.Minute)
		return true
	}

	return false
}

// hasSuspiciousBehavior vérifie des comportements suspects
func (bd *Firewall) hasSuspiciousBehavior(r *http.Request) bool {
	// Vérifier les tentatives d'accès à des fichiers sensibles
	suspiciousPaths := []string{
		".env",
		".git",
		".sql",
		"/.aws/",
		"/cgi-bin/",
		".cgi/",
	}

	path := strings.ToLower(r.URL.Path)
	for _, suspicious := range suspiciousPaths {
		if strings.Contains(path, suspicious) {
			return true
		}
	}

	return false
}

// isLegitimateBot vérifie si c'est un bot légitime (méthode interne)
func (bd *Firewall) isLegitimateBot(userAgent string) bool {
	for _, bot := range bd.legitimateBots {
		if strings.Contains(userAgent, bot) {
			return true
		}
	}
	return false
}

// blockIP bloque une IP pour une durée donnée
func (bd *Firewall) blockIP(ip string, duration time.Duration) {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	bd.blockedIPs[ip] = time.Now().Add(duration)
	log.Warn().Msg(fmt.Sprintf("🛡️	Ip '%s' bannie durant '%s'", ip, duration))
}

// isIPBlocked vérifie si une IP est bloquée
func (bd *Firewall) isIPBlocked(ip string) bool {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	if blockUntil, exists := bd.blockedIPs[ip]; exists {
		if time.Now().Before(blockUntil) {
			return true
		}
		// Nettoyer l'entrée expirée
		delete(bd.blockedIPs, ip)
	}
	return false
}

// Allow vérifie si une IP peut faire une requête (rate limiting)
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Nettoyer les anciennes requêtes
	if requests, exists := rl.requests[ip]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) <= rl.window {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.requests[ip] = validRequests

		// Vérifier la limite
		if len(validRequests) >= rl.limit {
			return false
		}
	}

	// Ajouter la nouvelle requête
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// getClientIP extrait l'IP réelle du client
func (bd *Firewall) GetClientIP(r *http.Request) string {
	// Vérifier les headers de proxy
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Prendre la première IP de la liste
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}

	// Sinon, utiliser RemoteAddr
	ip := r.RemoteAddr
	// Enlever le port si présent
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx]
	}
	return ip
}

// CleanupRoutine nettoie périodiquement les IPs bloquées expirées
func (bd *Firewall) CleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			bd.mu.Lock()
			now := time.Now()
			for ip, blockUntil := range bd.blockedIPs {
				if now.After(blockUntil) {
					delete(bd.blockedIPs, ip)
				}
			}
			bd.mu.Unlock()

			// Nettoyer aussi le rate limiter
			bd.rateLimiter.mu.Lock()
			for ip, requests := range bd.rateLimiter.requests {
				var validRequests []time.Time
				for _, reqTime := range requests {
					if now.Sub(reqTime) <= bd.rateLimiter.window {
						validRequests = append(validRequests, reqTime)
					}
				}
				if len(validRequests) == 0 {
					delete(bd.rateLimiter.requests, ip)
				} else {
					bd.rateLimiter.requests[ip] = validRequests
				}
			}
			bd.rateLimiter.mu.Unlock()
		}
	}()
}

// parseCommandLineArgs parses and validates command line arguments
func parseCommandLineArgs() (configFile string, shouldCreateExample bool, versionDisplay bool, err error) {
	var config = flag.String("config", "", "Fichier de configuration YAML")
	var example = flag.Bool("example", false, "Créer un fichier de configuration exemple")
	var version = flag.Bool("version", false, "version du produit")
	flag.Parse()

	if *version {
		return "", false, true, nil
	}

	if *example {
		return *config, true, false, nil
	}

	if *config == "" {
		return "", false, false, fmt.Errorf("fichier de configuration requis")
	}

	return *config, false, false, nil
}

func main() {
	// Parse command line arguments
	configFile, shouldCreateExample, versionDisplay, err := parseCommandLineArgs()
	if err != nil {
		fmt.Println("Usage:")
		fmt.Println("  hnProxy -config hnproxy.yaml")
		fmt.Println("  hnProxy -example  (pour créer un fichier exemple)")
		fmt.Println("  hnProxy -version  (affiche la version)")
		os.Exit(1)
	}

	if versionDisplay {
		println(VERSION)
		return
	}

	// Handle example creation
	if shouldCreateExample {
		if err := handleExampleCreation(configFile); err != nil {
			fmt.Printf("❌ %v\n", err)
		}
		return
	}

	// Load and validate configuration
	config, err := loadAndValidateConfig(configFile)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	initLogger(config.Logger, config.Production)

	// Create and configure server
	server := NewServer(config)
	server.DisplayConfiguration(configFile)

	// Start server
	if err := runServer(server); err != nil {
		log.Fatal().Msg(fmt.Sprintf("❌ Erreur serveur: %v", err))
	}
}
