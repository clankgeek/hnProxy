package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/syslog"
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

const VERSION string = "1.2.0"

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
	Listen     string           `yaml:"listen"`
	Firewall   *FirewallConfig  `yaml:"firewall"`
	TLS        *TLSConfig       `yaml:"tls,omitempty"`
	Routes     map[string]Route `yaml:"routes"`
	Logger     LoggerConfig     `yaml:"logger"`
	Production bool             `yaml:"production"`
}

type FirewallConfig struct {
	Enabled            bool                      `yaml:"enabled"`
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
	Firewall   *FirewallConfig
	TLS        *TLSConfig
	Routes     map[string]*BackendTarget
	Logger     LoggerConfig
	Production bool
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
	} else {
		writers = append(writers, os.Stdout)
	}

	// Writer pour le fichier si activé
	if cfg.File.Enable {
		fileWriter, err := setupFileWriter(cfg.File)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup file writer")
		}
		writers = append(writers, fileWriter)
	}

	// Wrtier syslog si activé
	if cfg.Syslog.Enable {
		syslogWriter, err := setupSyslogWriter(cfg.Syslog)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to setup syslog writer")
		}
		writers = append(writers, syslogWriter)
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
		Msg("Logger initialized")
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
func handleExampleCreation() error {
	filename := "hnproxy.yaml"
	if err := createExampleConfig(filename); err != nil {
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
		Firewall: &FirewallConfig{
			Enabled: true,
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
		Firewall:   yamlConfig.Firewall,
		TLS:        yamlConfig.TLS,
		Routes:     make(map[string]*BackendTarget),
		Logger:     yamlConfig.Logger,
		Production: yamlConfig.Production,
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
	if server.config.TLS != nil && server.config.TLS.Enabled {
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
	if s.config.TLS == nil || !s.config.TLS.Enabled {
		return fmt.Errorf("TLS non configuré")
	}

	// Setup HTTPS server
	server, err := s.createHTTPSServer()
	if err != nil {
		return fmt.Errorf("erreur création serveur HTTPS: %v", err)
	}

	// Start HTTP server for ACME challenges and redirects
	if s.config.TLS.ACME != nil {
		go s.startACMEHTTPServer()
	}
	log.Info().Msg("Serveur HTTPS démarré sur :443")

	if s.config.TLS.ACME != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	}
}

// createHTTPSServer creates the HTTPS server with proper TLS config
func (s *Server) createHTTPSServer() (*http.Server, error) {
	var tlsConfig *tls.Config

	if s.config.TLS.ACME != nil {
		manager, err := setupACME(s.config.TLS)
		if err != nil {
			return nil, fmt.Errorf("erreur configuration ACME: %v", err)
		}
		tlsConfig = manager.TLSConfig()
	}

	server := &http.Server{
		Addr:         ":443",
		Handler:      s.handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server, nil
}

// Handler pour rediriger HTTP vers HTTPS
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	LogPrintf("Redirection HTTP -> HTTPS: %s", target)
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// startACMEHTTPServer starts the HTTP server for ACME challenges and redirects
func (s *Server) startACMEHTTPServer() {
	manager, err := setupACME(s.config.TLS)
	if err != nil {
		LogPrintf("❌ Erreur ACME HTTP server: %v", err)
		return
	}

	httpMux := http.NewServeMux()
	httpMux.Handle("/.well-known/acme-challenge/", manager.HTTPHandler(nil))

	if s.config.TLS.RedirectHTTP {
		httpMux.HandleFunc("/", redirectToHTTPS)
	} else {
		httpMux.Handle("/", s.handler)
	}

	LogPrintf("🌐 Serveur HTTP démarré sur :80 (ACME + %s)",
		map[bool]string{true: "redirection", false: "proxy"}[s.config.TLS.RedirectHTTP])

	if err := http.ListenAndServe(":80", httpMux); err != nil {
		LogPrintf("❌ Erreur serveur HTTP: %v", err)
	}
}

// DisplayConfiguration shows the server configuration
func (s *Server) DisplayConfiguration(configFile string) {
	LogPrintf("hnProxy configuré")
	LogPrintf("Configuration: %s", configFile)

	firewall := false
	if s.config.Firewall != nil {
		withAntibot := s.config.Firewall.Antibot != nil && s.config.Firewall.Antibot.Enabled
		withRateLimiter := s.config.Firewall.RateLimiter != nil && s.config.Firewall.RateLimiter.Enabled

		if withAntibot || withRateLimiter {
			firewall = true
			LogPrintf("Firewall activé")
			if withRateLimiter {
				LogPrintf("  • Rate Limiter activé à %d requettes par minute", s.config.Firewall.RateLimiter.Limit)
			}
			if withAntibot {
				LogPrintf("  • Antibot activé ")
				if s.config.Firewall.Antibot.BlockLegitimeBots {
					LogPrintf("avec bloquage des bots légitimes")
				} else {
					LogPrintf("sans bloquage des bots légitimes")
				}
			}
		}

	}
	if !firewall {
		LogPrintf("Firewall désactivé")
	}

	if s.config.TLS != nil && s.config.TLS.Enabled {
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

	LogPrintf("Routes configurées:")
	protocol := "http"
	if s.config.TLS != nil && s.config.TLS.Enabled {
		protocol = "https"
	}

	for hostname, target := range s.config.Routes {
		backends := make([]string, len(target.URLs))
		for i, u := range target.URLs {
			backends[i] = u.String()
		}
		LogPrintf("  • %s://%s -> %v", protocol, hostname, backends)
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
	if rph.config.Firewall != nil && rph.config.Firewall.Enabled && rph.firewall != nil {
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

func (rph *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extraire le hostname (sans le port)
	hostname := strings.Split(r.Host, ":")[0]

	err := rph.Firewall(r)
	if err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		msg := err.Error()
		if msg != "" {
			log.Print(msg)
		}
		return
	}

	// Chercher la route correspondante
	target, exists := rph.config.Routes[hostname]
	if !exists {
		LogPrintf("❌ Aucune route trouvée pour hostname: %s", hostname)
		http.Error(w, "Nom d'hôte non configuré", http.StatusNotFound)
		return
	}

	// Sélectionner le backend
	backendURL := target.NextURL()
	if backendURL == nil {
		LogPrintf("❌ Aucun backend disponible pour %s", hostname)
		http.Error(w, "Aucun backend disponible", http.StatusServiceUnavailable)
		return
	}

	// Créer le reverse proxy pour cette requête
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host

			// Ajouter des headers utiles
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
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			LogPrintf("❌ Erreur proxy %s -> %s: %v", hostname, backendURL.String(), err)
			http.Error(w, "Service temporairement indisponible", http.StatusBadGateway)
		},
	}

	protocol := "HTTP"
	if r.TLS != nil {
		protocol = "HTTPS"
	}
	LogPrintf("🔀 [%s] %s%s -> %s", protocol, hostname, r.URL.Path, backendURL.String())
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

func NewFirewallConfig(withRateLimiter bool, limit int, withAntibot bool, withBlockLegitimeBots bool, withPatternsFiltering bool, withSuspiciousBehavior bool) *FirewallConfig {
	return &FirewallConfig{
		Enabled: true,
		RateLimiter: &RateLimiterConfig{
			Enabled: withRateLimiter,
			Limit:   100,
		},
		Antibot: &AntiBotsConfig{
			Enabled:           withAntibot,
			BlockLegitimeBots: withBlockLegitimeBots,
		},
		PatternsFiltering: &PatternsFilteringConfig{
			Enabled: withPatternsFiltering,
		},
		SuspiciousBehavior: &SuspiciousBehaviorConfig{
			Enabled: withSuspiciousBehavior,
		},
	}
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
	if bd.config.RateLimiter != nil && bd.config.RateLimiter.Enabled && !bd.rateLimiter.Allow(clientIP) {
		log.Warn().Msg(fmt.Sprintf("🛡️	Rate limit dépassé pour %s", clientIP))
		bd.blockIP(clientIP, 15*time.Minute)
		return true
	}
	return false
}

// IsBot vérifie si la requête provient d'un bot
func (bd *Firewall) IsBot(r *http.Request, clientIP string) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	LogPrintf("User Agent est : %s", userAgent)

	// Vérifier les bots légitimes SI on veut les bloquer
	if bd.config.Antibot != nil {
		if bd.config.Antibot.Enabled && bd.config.Antibot.BlockLegitimeBots {
			for _, bot := range bd.legitimateBots {
				if strings.Contains(userAgent, bot) {
					log.Warn().Msg(fmt.Sprintf("🛡️🤖	Bot légitime bloqué: %s depuis %s", bot, clientIP))
					// Blocage plus court pour les bots légitimes (ils reviendront)
					bd.blockIP(clientIP, 30*time.Minute)
					return true
				}
			}
		}

		// Vérifier les User-Agents de bots connus (malveillants)
		if bd.config.Antibot.Enabled {
			// Vérifier le User-Agent vide (suspect)
			if userAgent == "" {
				log.Warn().Msg(fmt.Sprintf("🛡️🤖	Bot détecté: User-Agent vide depuis %s", clientIP))
				bd.blockIP(clientIP, 1*time.Hour)
				return true
			}

			for _, botUA := range bd.botUserAgents {
				if strings.Contains(userAgent, botUA) {
					log.Warn().Msg(fmt.Sprintf("🛡️🤖	Bot malveillant détecté: %s depuis %s", botUA, clientIP))
					bd.blockIP(clientIP, 24*time.Hour)
					return true
				}
			}
		}
	}

	// Vérifier les patterns suspects
	if bd.config.PatternsFiltering != nil && bd.config.PatternsFiltering.Enabled {
		for _, pattern := range bd.suspiciousPatterns {
			if strings.Contains(userAgent, pattern) {
				// Si on ne bloque PAS les bots légitimes, vérifier si c'en est un
				if !bd.config.Antibot.BlockLegitimeBots && bd.isLegitimateBot(userAgent) {
					// C'est un bot légitime et on ne les bloque pas
					LogPrintf("Bot légitime autorisé: %s depuis %s", userAgent, clientIP)
					continue
				}
				// Sinon, c'est suspect et on bloque
				log.Warn().Msg(fmt.Sprintf("🛡️	Pattern suspect détecté: %s dans %s depuis %s", pattern, userAgent, clientIP))
				bd.blockIP(clientIP, 6*time.Hour)
				return true
			}
		}
	}

	// Vérifications additionnelles
	if bd.config.SuspiciousBehavior != nil && bd.config.SuspiciousBehavior.Enabled && bd.hasSuspiciousBehavior(r) {
		log.Warn().Msg(fmt.Sprintf("🛡️🤖	Comportement suspect détecté depuis %s", clientIP))
		bd.blockIP(clientIP, 30*time.Minute)
		return true
	}

	return false
}

// hasSuspiciousBehavior vérifie des comportements suspects
func (bd *Firewall) hasSuspiciousBehavior(r *http.Request) bool {
	// Vérifier l'absence de headers standards de navigateurs
	accept := r.Header.Get("Accept")
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")

	// Les vrais navigateurs envoient généralement ces headers
	if accept == "" || acceptLanguage == "" {
		return true
	}

	// Vérifier les tentatives d'accès à des fichiers sensibles
	suspiciousPaths := []string{
		".env",
		".git",
		".sql",
		"/.aws/",
	}

	path := strings.ToLower(r.URL.Path)
	for _, suspicious := range suspiciousPaths {
		if strings.Contains(path, suspicious) {
			return true
		}
	}

	// Vérifier la cohérence du Accept-Encoding
	if acceptEncoding != "" && !strings.Contains(acceptEncoding, "gzip") &&
		!strings.Contains(acceptEncoding, "deflate") && !strings.Contains(acceptEncoding, "br") {
		return true
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
		return "", true, false, nil
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
		if err := handleExampleCreation(); err != nil {
			fmt.Printf("❌ %v\n", err)
		}
		return
	}

	// Load and validate configuration
	config, err := loadAndValidateConfig(configFile)
	initLogger(config.Logger, config.Production)
	if err != nil {
		log.Fatal().Msg(fmt.Sprintf("❌ %v", err))
	}

	// Create and configure server
	server := NewServer(config)
	server.DisplayConfiguration(configFile)

	// Start server
	if err := runServer(server); err != nil {
		log.Fatal().Msg(fmt.Sprintf("❌ Erreur serveur: %v", err))
	}
}
