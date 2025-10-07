package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

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
	fmt.Printf("🌐 Serveur HTTP démarré sur %s\n", s.config.ListenAddr)
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

	fmt.Printf("🔒 Serveur HTTPS démarré sur :443\n")

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
	log.Printf("🔄 Redirection HTTP -> HTTPS: %s", target)
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// startACMEHTTPServer starts the HTTP server for ACME challenges and redirects
func (s *Server) startACMEHTTPServer() {
	manager, err := setupACME(s.config.TLS)
	if err != nil {
		log.Printf("❌ Erreur ACME HTTP server: %v", err)
		return
	}

	httpMux := http.NewServeMux()
	httpMux.Handle("/.well-known/acme-challenge/", manager.HTTPHandler(nil))

	if s.config.TLS.RedirectHTTP {
		httpMux.HandleFunc("/", redirectToHTTPS)
	} else {
		httpMux.Handle("/", s.handler)
	}

	fmt.Printf("🌐 Serveur HTTP démarré sur :80 (ACME + %s)\n",
		map[bool]string{true: "redirection", false: "proxy"}[s.config.TLS.RedirectHTTP])

	if err := http.ListenAndServe(":80", httpMux); err != nil {
		log.Printf("❌ Erreur serveur HTTP: %v", err)
	}
}

// DisplayConfiguration shows the server configuration
func (s *Server) DisplayConfiguration(configFile string) {
	fmt.Printf("🚀 hnProxy configuré\n")
	fmt.Printf("📋 Configuration: %s\n", configFile)

	firewall := false
	if s.config.Firewall != nil {
		withAntibot := s.config.Firewall.Antibot != nil && s.config.Firewall.Antibot.Enabled
		withRateLimiter := s.config.Firewall.RateLimiter != nil && s.config.Firewall.RateLimiter.Enabled

		if withAntibot || withRateLimiter {
			firewall = true
			fmt.Printf("🛡️ Firewall activé\n")
			if withRateLimiter {
				fmt.Printf("  • Rate Limiter activé à %d requettes par minute\n", s.config.Firewall.RateLimiter.Limit)
			}
			if withAntibot {
				fmt.Printf("  • 🤖 Antibot activé ")
				if s.config.Firewall.Antibot.BlockLegitimeBots {
					fmt.Printf("avec bloquage des bots légitimes\n")
				} else {
					fmt.Printf("sans bloquage des bots légitimes\n")
				}
			}
		}

	}
	if !firewall {
		fmt.Printf("🛡️ Firewall désactivé\n")
	}

	if s.config.TLS != nil && s.config.TLS.Enabled {
		fmt.Printf("🔒 HTTPS activé\n")
		if s.config.TLS.ACME != nil {
			fmt.Printf("🤖 ACME configuré pour: %v\n", s.config.TLS.ACME.Domains)
			fmt.Printf("📧 Email: %s\n", s.config.TLS.ACME.Email)
			fmt.Printf("📁 Cache: %s\n", s.config.TLS.ACME.CacheDir)
		} else {
			fmt.Printf("📜 Certificats: %s, %s\n", s.config.TLS.CertFile, s.config.TLS.KeyFile)
		}
	} else {
		fmt.Printf("🌐 Mode HTTP\n")
	}

	fmt.Println("📋 Routes configurées:")
	protocol := "http"
	if s.config.TLS != nil && s.config.TLS.Enabled {
		protocol = "https"
	}

	for hostname, target := range s.config.Routes {
		backends := make([]string, len(target.URLs))
		for i, u := range target.URLs {
			backends[i] = u.String()
		}
		fmt.Printf("  • %s://%s -> %v\n", protocol, hostname, backends)
	}
}
