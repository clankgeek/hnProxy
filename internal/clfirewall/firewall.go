package clfirewall

import (
	"bufio"
	"fmt"
	"hnproxy/internal/clconfig"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Firewall gère la détection et le blocage des bots
type Firewall struct {
	Config *clconfig.FirewallConfig

	// Liste des User-Agents de bots connus
	botUserAgents map[string]bool

	// Liste des IP bloquées
	blockedIPs map[string]time.Time
	mu         sync.RWMutex

	// Patterns suspects dans les User-Agents
	suspiciousPatterns []string

	// Liste des bots légitimes
	legitimateBots map[string]bool

	// Liste des bots IA
	iaBots map[string]bool

	rateLimiter *RateLimiter

	GeoDB *geoip2.Reader

	Redis *redis.Client

	IPBlockList map[string]struct{}
}

// RateLimiter pour limiter le nombre de requêtes par IP
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int           // Nombre max de requêtes
	window   time.Duration // Fenêtre de temps
}

// NewFirewall crée une nouvelle instance de Firewall
func NewFirewall(config *clconfig.FirewallConfig) *Firewall {
	var geodb *geoip2.Reader
	var redisClient *redis.Client
	var err error

	if config.GeolocationFiltering != nil && config.GeolocationFiltering.Enabled && config.GeolocationFiltering.DatabasePath != "" {
		geodb, err = geoip2.Open(config.GeolocationFiltering.DatabasePath)
		if err != nil {
			log.Fatal().Err(err).Msg("Erreur lors du chargement de la base de données GeoIP")
		}
	}

	if config.Redis != nil && config.Redis.Addr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr: config.Redis.Addr,
			DB:   config.Redis.Db,
		})
	}

	fw := &Firewall{
		Config:         config,
		legitimateBots: make(map[string]bool),
		iaBots:         make(map[string]bool),
		botUserAgents:  make(map[string]bool),
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
		GeoDB:       geodb,
		Redis:       redisClient,
		IPBlockList: make(map[string]struct{}),
	}

	for _, ua := range botUserAgents {
		fw.botUserAgents[ua] = true
	}

	for _, bot := range legitimateBots {
		fw.legitimateBots[bot] = true
	}

	for _, iaBot := range iaBots {
		fw.iaBots[iaBot] = true
	}

	if fw.Config.IPBlockListConfig != nil && fw.Config.IPBlockListConfig.Enabled {
		path := fw.Config.IPBlockListConfig.DatabasePath
		url := fw.Config.IPBlockListConfig.DatabaseURL
		if path == "" && url != "" {
			if url != "" {
				path = fw.DownloadFile(url)
				if path == "" {
					log.Warn().Msg("Échec du téléchargement de la blocklist IP, le module IPBlockList sera désactivé")
					return fw
				}
				defer os.Remove(path) // Nettoyer le fichier temporaire après utilisation
				log.Info().Msg(fmt.Sprintf("✅ Blocklist IP téléchargée et prête à être chargée depuis '%s'", path))
				fw.LoadBlocklist(path)
				go fw.startBlocklistAutoRefresh(url)
				return fw
			} else {
				log.Warn().Msg("Aucun chemin ou URL fourni pour la blocklist IP, le module IPBlockList sera désactivé")
				return fw
			}
		} else {
			log.Info().Msg(fmt.Sprintf("✅ Blocklist IP chargée depuis le chemin local '%s'", path))
		}
		fw.LoadBlocklist(path)
	}

	return fw
}

func (bd *Firewall) DownloadFile(url string) (path string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Error().Err(err).Msg("Erreur lors du téléchargement de la blocklist IP")
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status", resp.StatusCode).Msg("Réponse HTTP invalide lors du téléchargement de la blocklist IP")
		return ""
	}

	tmpFile, err := os.CreateTemp("", "ipblocklist-*.txt")
	if err != nil {
		log.Error().Err(err).Msg("Erreur lors de la création du fichier temporaire pour la blocklist IP")
		return ""
	}
	defer tmpFile.Close()

	if _, err = io.Copy(tmpFile, resp.Body); err != nil {
		log.Error().Err(err).Msg("Erreur lors de l'écriture de la blocklist IP")
		return ""
	}

	path = tmpFile.Name()
	return path
}

func (bd *Firewall) LoadBlocklist(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Error().Err(err).Msg("Erreur lors du chargement de la blocklist IP")
		return
	}
	defer file.Close()

	bd.mu.Lock()
	defer bd.mu.Unlock()

	bd.IPBlockList = make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			bd.IPBlockList[ip] = struct{}{}
		}
	}
	if scanner.Err() != nil {
		log.Error().Err(scanner.Err()).Msg("Erreur lors de la lecture de la blocklist IP")
	} else {
		log.Info().Msg(fmt.Sprintf("✅ Blocklist IP chargée avec succès depuis '%s' (%d IPs)", path, len(bd.IPBlockList)))
	}
}

// startBlocklistAutoRefresh télécharge et recharge la blocklist IP toutes les 24h.
func (bd *Firewall) startBlocklistAutoRefresh(url string) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		log.Info().Msg("🔄 Mise à jour automatique de la blocklist IP (24h)")
		path := bd.DownloadFile(url)
		if path == "" {
			log.Warn().Msg("Échec du téléchargement de la blocklist IP lors de la mise à jour automatique")
			continue
		}
		bd.LoadBlocklist(path)
		os.Remove(path)
	}
}

func (bd *Firewall) IsIPInBlocklist(clientIP string) bool {
	if bd.Config.IPBlockListConfig == nil || !bd.Config.IPBlockListConfig.Enabled {
		return false
	}
	bd.mu.RLock()
	defer bd.mu.RUnlock()
	if _, blocked := bd.IPBlockList[clientIP]; blocked {
		log.Warn().Msg(fmt.Sprintf("🛡️ Requête bloquée par le module IPBlockList pour l'IP '%s'", clientIP))
		return true
	}
	return false
}

func (bd *Firewall) IsLimiter(clientIP string) bool {
	if bd.Config.RateLimiter.Enabled && !bd.rateLimiter.Allow(clientIP) {
		log.Warn().Msg(fmt.Sprintf("🛡️ Rate limit dépassé pour %s", clientIP))
		bd.blockIP(clientIP, 15*time.Minute)
		return true
	}
	return false
}

// IsBot vérifie si la requête provient d'un bot
func (bd *Firewall) IsBot(r *http.Request, clientIP string) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	log.Debug().Msg(fmt.Sprintf("🤖 User Agent est : %s", userAgent))

	if bd.Config.Antibot.Enabled {
		// Vérifier les bots légitimes SI on veut les bloquer
		if bd.Config.Antibot.BlockLegitimeBots {
			for bot := range bd.legitimateBots {
				if strings.Contains(userAgent, bot) {
					log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot légitime bloqué: %s depuis %s", bot, clientIP))
					// Blocage plus court pour les bots légitimes (ils reviendront)
					bd.blockIP(clientIP, 30*time.Minute)
					return true
				}
			}
		}

		if bd.Config.Antibot.BlockIABots {
			for iaBot := range bd.iaBots {
				if strings.Contains(userAgent, iaBot) {
					log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot IA bloqué: %s depuis %s", iaBot, clientIP))
					// Blocage plus long pour les bots IA (moins légitimes)
					bd.blockIP(clientIP, 1*time.Hour)
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
		for botUA := range bd.botUserAgents {
			if strings.Contains(userAgent, botUA) {
				log.Warn().Msg(fmt.Sprintf("🛡️🤖 Bot malveillant détecté: %s depuis %s", botUA, clientIP))
				bd.blockIP(clientIP, 24*time.Hour)
				return true
			}
		}
	}

	// Vérifier les patterns suspects
	if bd.Config.PatternsFiltering.Enabled {
		for _, pattern := range bd.suspiciousPatterns {
			if strings.Contains(userAgent, pattern) {
				// Si on ne bloque PAS les bots légitimes, vérifier si c'en est un
				if !bd.Config.Antibot.BlockLegitimeBots && bd.isLegitimateBot(userAgent) {
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
	if bd.Config.SuspiciousBehavior.Enabled && bd.hasSuspiciousBehavior(r) {
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
		"/wp-good.php",       // backdoors
		"/autoload_classmap", // backdoors
	}

	if bd.Config.SuspiciousBehavior.WordpressRemover {
		suspiciousPaths = append(suspiciousPaths, "/wp-login.php", "/wp-admin/", "/xmlrpc.php")
	}

	path := strings.ToLower(r.URL.Path)
	for _, suspicious := range suspiciousPaths {
		if strings.Contains(path, suspicious) {
			return true
		}
	}

	return false
}

func (bd *Firewall) setRedisValue(r *http.Request, ipKey string, value string) bool {
	if bd.Redis == nil {
		return value == "true"
	}
	bd.Redis.Set(r.Context(), ipKey, value, 1*time.Hour)
	return value == "true"
}

func (bd *Firewall) IsGeolocationBlock(r *http.Request, clientIP string) bool {
	if bd.GeoDB == nil {
		return false
	}

	parsedIP, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	ipKey := fmt.Sprintf("geoloc:ip:%s", parsedIP)

	if bd.Redis != nil {
		val := bd.Redis.Get(r.Context(), ipKey).Val()
		if val != "" {
			return val == "true"
		}
	}

	record, err := bd.GeoDB.Country(parsedIP)
	if err != nil {
		return bd.setRedisValue(r, ipKey, "false")
	}

	countryCode := record.Country.ISOCode

	for _, allowedCountry := range bd.Config.GeolocationFiltering.AllowedCountries {
		if strings.EqualFold(countryCode, allowedCountry) {
			return bd.setRedisValue(r, ipKey, "false")
		}
	}

	if bd.Config.GeolocationFiltering.NotAllowedActionBlock {
		log.Warn().Msg(fmt.Sprintf("🛡️ Requête bloquée depuis le pays '%s' pour l'IP '%s'", countryCode, clientIP))
		bd.blockIP(clientIP, 24*time.Hour)
		return bd.setRedisValue(r, ipKey, "true")
	}

	for _, blockedCountry := range bd.Config.GeolocationFiltering.DisallowedCountries {
		if strings.EqualFold(countryCode, blockedCountry) {
			log.Warn().Msg(fmt.Sprintf("🛡️ Requête bloquée depuis le pays '%s' pour l'IP '%s'", countryCode, clientIP))
			bd.blockIP(clientIP, 24*time.Hour)
			return bd.setRedisValue(r, ipKey, "true")
		}
	}

	return bd.setRedisValue(r, ipKey, "false")
}

// isLegitimateBot vérifie si c'est un bot légitime (méthode interne)
func (bd *Firewall) isLegitimateBot(userAgent string) bool {
	for bot := range bd.legitimateBots {
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
	log.Warn().Msg(fmt.Sprintf("🛡️ Ip '%s' bannie durant '%s'", ip, duration))
}

// isIPBlocked vérifie si une IP est bloquée
func (bd *Firewall) IsIPBlocked(ip string) bool {
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

func (bd *Firewall) GetClientIP(r *http.Request) string {
	// 1. Cloudflare (priorité haute car très fiable)
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// 2. Header True-Client-IP (utilisé par Cloudflare Enterprise, Akamai)
	if ip := r.Header.Get("True-Client-IP"); ip != "" {
		return ip
	}

	// 3. X-Real-IP (Nginx, certains load balancers)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// 4. X-Forwarded-For (standard de facto)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Première IP = client original
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// 5. Fallback sur RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Pas de port, retourner tel quel
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
