package clrp

import (
	"context"
	"errors"
	"fmt"
	"hnproxy/internal/clconfig"
	"hnproxy/internal/clfirewall"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Reverse Proxy Handler
type ReverseProxyHandler struct {
	Config   *clconfig.ProxyConfig
	Firewall *clfirewall.Firewall
}

func NewReverseProxyHandler(config *clconfig.ProxyConfig, firewall *clfirewall.Firewall) *ReverseProxyHandler {
	return &ReverseProxyHandler{
		Config:   config,
		Firewall: firewall,
	}
}

func (rph *ReverseProxyHandler) FirewallRequest(r *http.Request) error {
	if rph.Config.Firewall.Enabled && rph.Firewall != nil {
		clientIp := rph.Firewall.GetClientIP(r)
		if rph.Firewall.IsIPBlocked(clientIp) {
			return fmt.Errorf("")
		}
		if rph.Firewall.IsLimiter(r, clientIp) {
			return fmt.Errorf("🚫 Requette rejetée par le firewall, module ratelimiter")
		}
		if rph.Firewall.IsBot(r, clientIp) {
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

	host, port := GetHostname(r, rph.Config)
	if host != hostname {
		if port != "" {
			host = host + ":" + port
		}
		Redirection(host, w, r)
		return
	}

	err := rph.FirewallRequest(r)
	if err != nil {
		msg := err.Error()
		if msg != "" {
			log.Error().Msg(msg)
		}
		switch rph.Firewall.Config.BlockMessage {
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
	target, exists := rph.Config.Routes[hostname]
	if !exists {
		log.Debug().Msg(fmt.Sprintf("❌ Invalid hostname: source: %s, hostname: %s", rph.Firewall.GetClientIP(r), r.Host))
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

func GetHostname(r *http.Request, config *clconfig.ProxyConfig) (string, string) {
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

func Redirection(hostname string, w http.ResponseWriter, r *http.Request) {
	target := "https://" + hostname + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
