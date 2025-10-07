package main

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

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
		log.Printf("🛡️	Rate limit dépassé pour %s", clientIP)
		bd.blockIP(clientIP, 15*time.Minute)
		return true
	}
	return false
}

// IsBot vérifie si la requête provient d'un bot
func (bd *Firewall) IsBot(r *http.Request, clientIP string) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	log.Printf("User Agent est : %s", userAgent)

	// Vérifier les bots légitimes SI on veut les bloquer
	if bd.config.Antibot != nil {
		if bd.config.Antibot.Enabled && bd.config.Antibot.BlockLegitimeBots {
			for _, bot := range bd.legitimateBots {
				if strings.Contains(userAgent, bot) {
					log.Printf("🛡️🤖	Bot légitime bloqué: %s depuis %s", bot, clientIP)
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
				log.Printf("🛡️🤖	Bot détecté: User-Agent vide depuis %s", clientIP)
				bd.blockIP(clientIP, 1*time.Hour)
				return true
			}

			for _, botUA := range bd.botUserAgents {
				if strings.Contains(userAgent, botUA) {
					log.Printf("🛡️🤖	Bot malveillant détecté: %s depuis %s", botUA, clientIP)
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
					log.Printf("Bot légitime autorisé: %s depuis %s", userAgent, clientIP)
					continue
				}
				// Sinon, c'est suspect et on bloque
				log.Printf("🛡️	Pattern suspect détecté: %s dans %s depuis %s", pattern, userAgent, clientIP)
				bd.blockIP(clientIP, 6*time.Hour)
				return true
			}
		}
	}

	// Vérifications additionnelles
	if bd.config.SuspiciousBehavior != nil && bd.config.SuspiciousBehavior.Enabled && bd.hasSuspiciousBehavior(r) {
		log.Printf("🛡️🤖	Comportement suspect détecté depuis %s", clientIP)
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
	log.Printf("🛡️	Ip '%s' bannie durant '%s'", ip, duration)
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
