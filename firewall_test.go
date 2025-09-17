package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewFirewall vérifie la création d'une nouvelle instance de Firewall
func TestNewFirewall(t *testing.T) {
	tests := []struct {
		name              string
		blockLegitimeBots bool
	}{
		{"avec blocage bots légitimes", true},
		{"sans blocage bots légitimes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := NewFirewall(tt.blockLegitimeBots)

			if fw == nil {
				t.Fatal("NewFirewall a retourné nil")
			}

			if fw.blockLegitimeBots != tt.blockLegitimeBots {
				t.Errorf("blockLegitimeBots = %v, attendu %v",
					fw.blockLegitimeBots, tt.blockLegitimeBots)
			}

			if fw.blockedIPs == nil {
				t.Error("blockedIPs n'est pas initialisé")
			}

			if fw.rateLimiter == nil {
				t.Error("rateLimiter n'est pas initialisé")
			}

			if fw.rateLimiter.requests == nil {
				t.Error("rateLimiter.requests n'est pas initialisé")
			}
		})
	}
}

// TestIsBot_UserAgentVide teste la détection d'un User-Agent vide
func TestIsBot_UserAgentVide(t *testing.T) {
	fw := NewFirewall(false)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "")

	if !fw.IsBot(req, "192.168.1.1") {
		t.Error("Un User-Agent vide devrait être détecté comme bot")
	}

	if !fw.isIPBlocked("192.168.1.1") {
		t.Error("L'IP devrait être bloquée après détection d'User-Agent vide")
	}
}

// TestIsBot_BotsMalveillants teste la détection des bots malveillants
func TestIsBot_BotsMalveillants(t *testing.T) {
	fw := NewFirewall(false)

	botUserAgents := []string{
		"python-requests/2.28.0",
		"curl/7.68.0",
		"Scrapy/2.5.0",
		"sqlmap/1.5.2",
		"nikto/2.1.5",
		"masscan/1.3.0",
	}

	for _, ua := range botUserAgents {
		t.Run(ua, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", ua)

			if !fw.IsBot(req, "192.168.1."+ua) {
				t.Errorf("User-Agent %s devrait être détecté comme bot", ua)
			}
		})
	}
}

// TestIsBot_BotsLegitimes teste le comportement avec les bots légitimes
func TestIsBot_BotsLegitimes(t *testing.T) {
	tests := []struct {
		name              string
		blockLegitimeBots bool
		userAgent         string
		shouldBlock       bool
	}{
		{
			"Googlebot autorisé",
			false,
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			false,
		},
		{
			"Googlebot bloqué",
			true,
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			true,
		},
		{
			"Bingbot autorisé",
			false,
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			false,
		},
		{
			"Bingbot bloqué",
			true,
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			true,
		},
		{
			"FacebookBot autorisé",
			false,
			"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := NewFirewall(tt.blockLegitimeBots)
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")

			result := fw.IsBot(req, "192.168.1.100")
			if result != tt.shouldBlock {
				t.Errorf("IsBot() = %v, attendu %v", result, tt.shouldBlock)
			}
		})
	}
}

// TestHasSuspiciousBehavior teste la détection de comportements suspects
func TestHasSuspiciousBehavior(t *testing.T) {
	fw := NewFirewall(false)

	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		suspicious bool
	}{
		{
			"Headers normaux",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html,application/xhtml+xml")
				r.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
				r.Header.Set("Accept-Encoding", "gzip, deflate, br")
			},
			false,
		},
		{
			"Accept manquant",
			func(r *http.Request) {
				r.Header.Set("Accept-Language", "fr-FR")
			},
			true,
		},
		{
			"Accept-Language manquant",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html")
			},
			true,
		},
		{
			"Accept-Encoding suspect",
			func(r *http.Request) {
				r.Header.Set("Accept", "text/html")
				r.Header.Set("Accept-Language", "en")
				r.Header.Set("Accept-Encoding", "weird-encoding")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			result := fw.hasSupiciousBehavior(req)
			if result != tt.suspicious {
				t.Errorf("hasSupiciousBehavior() = %v, attendu %v", result, tt.suspicious)
			}
		})
	}
}

// TestHasSuspiciousBehavior_PathsSensibles teste la détection d'accès à des fichiers sensibles
func TestHasSuspiciousBehavior_PathsSensibles(t *testing.T) {
	fw := NewFirewall(false)

	suspiciousPaths := []string{
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/.aws/credentials",
		"/admin/.env",
	}

	for _, path := range suspiciousPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")

			if !fw.hasSupiciousBehavior(req) {
				t.Errorf("Le chemin %s devrait être détecté comme suspect", path)
			}
		})
	}

	// Tester un chemin normal
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")

	if fw.hasSupiciousBehavior(req) {
		t.Error("Un chemin normal ne devrait pas être suspect")
	}
}

// TestRateLimiter_Allow teste le fonctionnement du rate limiter
func TestRateLimiter_Allow(t *testing.T) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    3,
		window:   100 * time.Millisecond,
	}

	ip := "192.168.1.1"

	// Les premières requêtes doivent passer
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Errorf("La requête %d devrait être autorisée", i+1)
		}
	}

	// La 4ème requête devrait être bloquée
	if rl.Allow(ip) {
		t.Error("La 4ème requête devrait être bloquée")
	}

	// Attendre que la fenêtre expire
	time.Sleep(150 * time.Millisecond)

	// Maintenant la requête devrait passer
	if !rl.Allow(ip) {
		t.Error("La requête devrait être autorisée après expiration de la fenêtre")
	}
}

// TestRateLimiter_Concurrent teste le rate limiter en conditions concurrentes
func TestRateLimiter_Concurrent(t *testing.T) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    10,
		window:   100 * time.Millisecond,
	}

	var wg sync.WaitGroup
	allowed := 0
	blocked := 0
	var mu sync.Mutex

	// Lancer 20 goroutines simultanées
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("192.168.1.1") {
				mu.Lock()
				allowed++
				mu.Unlock()
			} else {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if allowed > 10 {
		t.Errorf("Plus de requêtes autorisées que la limite: %d > 10", allowed)
	}

	if allowed+blocked != 20 {
		t.Errorf("Total incorrect: allowed=%d, blocked=%d", allowed, blocked)
	}
}

// TestIsLimiter teste la méthode IsLimiter
func TestIsLimiter(t *testing.T) {
	fw := NewFirewall(false)
	fw.rateLimiter.limit = 2
	fw.rateLimiter.window = 100 * time.Millisecond

	req := httptest.NewRequest("GET", "/", nil)
	ip := "192.168.1.1"

	// Les premières requêtes ne devraient pas déclencher le limiter
	for i := 0; i < 2; i++ {
		if fw.IsLimiter(req, ip) {
			t.Errorf("La requête %d ne devrait pas être limitée", i+1)
		}
	}

	// La 3ème requête devrait déclencher le limiter
	if !fw.IsLimiter(req, ip) {
		t.Error("La 3ème requête devrait être limitée")
	}

	// L'IP devrait maintenant être bloquée
	if !fw.isIPBlocked(ip) {
		t.Error("L'IP devrait être bloquée après dépassement du rate limit")
	}
}

// TestBlockIP_Duration teste le blocage temporaire des IPs
func TestBlockIP_Duration(t *testing.T) {
	fw := NewFirewall(false)
	ip := "192.168.1.1"

	// Bloquer l'IP pour 50ms
	fw.blockIP(ip, 50*time.Millisecond)

	if !fw.isIPBlocked(ip) {
		t.Error("L'IP devrait être bloquée immédiatement")
	}

	// Attendre que le blocage expire
	time.Sleep(60 * time.Millisecond)

	if fw.isIPBlocked(ip) {
		t.Error("L'IP ne devrait plus être bloquée après expiration")
	}
}

// TestGetClientIP teste l'extraction de l'IP cliente
func TestGetClientIP(t *testing.T) {
	fw := NewFirewall(false)

	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			"X-Real-IP",
			func(r *http.Request) {
				r.Header.Set("X-Real-IP", "203.0.113.1")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.1",
		},
		{
			"X-Forwarded-For simple",
			func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.2")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.2",
		},
		{
			"X-Forwarded-For multiple",
			func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "203.0.113.3, 10.0.0.1, 192.168.1.1")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"203.0.113.3",
		},
		{
			"RemoteAddr avec port",
			func(r *http.Request) {
				r.RemoteAddr = "192.168.1.1:12345"
			},
			"192.168.1.1",
		},
		{
			"RemoteAddr sans port",
			func(r *http.Request) {
				r.RemoteAddr = "192.168.1.1"
			},
			"192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tt.setupReq(req)

			ip := fw.GetClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("GetClientIP() = %v, attendu %v", ip, tt.expectedIP)
			}
		})
	}
}

// TestCleanupRoutine teste le nettoyage périodique
func TestCleanupRoutine(t *testing.T) {
	fw := NewFirewall(false)

	// Bloquer quelques IPs avec des durées courtes
	fw.blockIP("192.168.1.1", 50*time.Millisecond)
	fw.blockIP("192.168.1.2", 100*time.Millisecond)
	fw.blockIP("192.168.1.3", 10*time.Second) // Cette IP restera bloquée

	// Ajouter des requêtes au rate limiter
	fw.rateLimiter.window = 50 * time.Millisecond
	fw.rateLimiter.Allow("10.0.0.1")
	fw.rateLimiter.Allow("10.0.0.2")

	// Lancer la routine de nettoyage
	fw.CleanupRoutine()

	// Attendre un peu pour que les blocages expirent
	time.Sleep(150 * time.Millisecond)

	// Forcer un nettoyage manuel pour le test
	fw.mu.Lock()
	now := time.Now()
	for ip, blockUntil := range fw.blockedIPs {
		if now.After(blockUntil) {
			delete(fw.blockedIPs, ip)
		}
	}
	fw.mu.Unlock()

	// Vérifier que les IPs expirées sont nettoyées
	if fw.isIPBlocked("192.168.1.1") {
		t.Error("L'IP 192.168.1.1 ne devrait plus être bloquée")
	}

	if fw.isIPBlocked("192.168.1.2") {
		t.Error("L'IP 192.168.1.2 ne devrait plus être bloquée")
	}

	// Cette IP devrait toujours être bloquée
	if !fw.isIPBlocked("192.168.1.3") {
		t.Error("L'IP 192.168.1.3 devrait toujours être bloquée")
	}
}

// TestIsLegitimateBot teste la détection des bots légitimes
func TestIsLegitimateBot(t *testing.T) {
	fw := NewFirewall(false)

	tests := []struct {
		userAgent    string
		isLegitimate bool
	}{
		{"mozilla/5.0 (compatible; googlebot/2.1)", true},
		{"bingbot/2.0", true},
		{"facebookexternalhit/1.1", true},
		{"twitterbot/1.0", true},
		{"random-bot/1.0", false},
		{"mozilla/5.0 firefox", false},
		{"python-requests/2.28.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.userAgent, func(t *testing.T) {
			result := fw.isLegitimateBot(strings.ToLower(tt.userAgent))
			if result != tt.isLegitimate {
				t.Errorf("isLegitimateBot(%s) = %v, attendu %v",
					tt.userAgent, result, tt.isLegitimate)
			}
		})
	}
}

// TestPatternsSuspects teste la détection basée sur les patterns
func TestPatternsSuspects(t *testing.T) {
	fw := NewFirewall(false)

	tests := []struct {
		name        string
		userAgent   string
		shouldBlock bool
	}{
		{
			"Pattern bot générique",
			"some-bot/1.0",
			true,
		},
		{
			"Pattern crawler",
			"web-crawler/2.0",
			true,
		},
		{
			"Pattern spider",
			"spider-engine/1.0",
			true,
		},
		{
			"Pattern scraper",
			"data-scraper/3.0",
			true,
		},
		{
			"Navigateur normal",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")

			result := fw.IsBot(req, "192.168.1.100")
			if result != tt.shouldBlock {
				t.Errorf("IsBot() = %v, attendu %v pour %s",
					result, tt.shouldBlock, tt.userAgent)
			}
		})
	}
}

// BenchmarkIsBot teste les performances de IsBot
func BenchmarkIsBot(b *testing.B) {
	fw := NewFirewall(false)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.IsBot(req, "192.168.1.1")
	}
}

// BenchmarkRateLimiter teste les performances du rate limiter
func BenchmarkRateLimiter(b *testing.B) {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    100,
		window:   time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("192.168.1.1")
	}
}
