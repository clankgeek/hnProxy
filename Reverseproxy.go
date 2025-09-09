package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Reverse Proxy Handler
type ReverseProxyHandler struct {
	config *ProxyConfig
}

func NewReverseProxyHandler(config *ProxyConfig) *ReverseProxyHandler {
	return &ReverseProxyHandler{config: config}
}

func (rph *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extraire le hostname (sans le port)
	hostname := strings.Split(r.Host, ":")[0]

	// Chercher la route correspondante
	target, exists := rph.config.Routes[hostname]
	if !exists {
		log.Printf("❌ Aucune route trouvée pour hostname: %s", hostname)
		http.Error(w, "Nom d'hôte non configuré", http.StatusNotFound)
		return
	}

	// Sélectionner le backend
	backendURL := target.NextURL()
	if backendURL == nil {
		log.Printf("❌ Aucun backend disponible pour %s", hostname)
		http.Error(w, "Aucun backend disponible", http.StatusServiceUnavailable)
		return
	}

	// Créer le reverse proxy pour cette requête
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
			req.Host = backendURL.Host

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
			log.Printf("❌ Erreur proxy %s -> %s: %v", hostname, backendURL.String(), err)
			http.Error(w, "Service temporairement indisponible", http.StatusBadGateway)
		},
	}

	protocol := "HTTP"
	if r.TLS != nil {
		protocol = "HTTPS"
	}
	log.Printf("🔀 [%s] %s%s -> %s", protocol, hostname, r.URL.Path, backendURL.String())
	proxy.ServeHTTP(w, r)
}
