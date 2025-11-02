package clserver

import (
	"crypto/tls"
	"fmt"
	"hnproxy/internal/clconfig"
	"hnproxy/internal/clfirewall"
	"hnproxy/internal/clrp"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	config  *clconfig.ProxyConfig
	handler *clrp.ReverseProxyHandler
}

// NewServer creates a new server instance
func NewServer(config *clconfig.ProxyConfig) *Server {
	var firewall *clfirewall.Firewall
	if config.Firewall != nil && config.Firewall.Enabled {
		firewall = clfirewall.NewFirewall(config.Firewall)
		firewall.CleanupRoutine()
	}
	return &Server{
		config:  config,
		handler: clrp.NewReverseProxyHandler(config, firewall),
	}
}

// runServer starts the appropriate server based on configuration
func RunServer(server *Server) error {
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

func validateHostname(h string, config *clconfig.ProxyConfig, handler *clrp.ReverseProxyHandler, r *http.Request) bool {
	if _, exists := config.Routes[h]; !exists {
		log.Debug().Msg(fmt.Sprintf("❌ Invalid hostname (redirection): source: %s, hostname: %s path: %s", handler.Firewall.GetClientIP(r), h, r.URL.Path))
		return false
	}
	return true
}

// Handler pour rediriger HTTP vers HTTPS
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	host, port := clrp.GetHostname(r, s.config)

	if !validateHostname(host, s.config, s.handler, r) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	if port != "" {
		host = host + ":" + port
	}
	log.Debug().Msg(fmt.Sprintf("Redirection HTTP vers HTTPS %s", host))
	clrp.Redirection(host, w, r)
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

// Info logue avec printf
func LogPrintf(format string, a ...any) {
	log.Info().Msg(fmt.Sprintf(format, a...))
}

// Configurer ACME autocert
func setupACME(tlsConfig *clconfig.TLSConfig, production bool) (*autocert.Manager, error) {
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
