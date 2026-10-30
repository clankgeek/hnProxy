# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

## [1.3.1] - 2026-10-31

- Fix: correction d'un crash concurrent (`RLock`) lors de la vérification des IPs bannies
- Fix: prise en compte de la limite configurée pour le rate limiter
- Fix: transmission de l'IP cliente au backend (`X-Real-IP`, `X-Forwarded-For`) et suppression des headers falsifiables
- Fix: partage d'une instance unique `autocert.Manager` entre HTTP et HTTPS
- Perf: mutualisation du `http.Transport` (réutilisation des connexions Keep-Alive vers les backends)
- Sécurité: ajout de timeouts HTTP/HTTPS anti-Slowloris et limitation de concurrence sur le mode `slowfake`
- Sécurité: exécution du firewall avant les redirections et sécurisation du téléchargement des blocklists IP
- Ajout: arrêt gracieux du serveur (`SIGINT`/`SIGTERM`) et fermeture propre des ressources

## [1.3.0] - 2026-07-11

- Filtrage via une base ip reputation.

## [1.2.0] - 2025-12-18
- choix du blockmessage, avec 403, 404, 418 ou slowfake
- filtrage des patterns wordpress si on ne l'utilise pas
- filtrage des pays via geoloc en liste autorisée ou non autorisée
- Redis (en option) pour le stockage des données de session (geoloc, etc)
- Filtrage antibot pour les bots IA (ChatGPT, Bard, etc)

## [1.1.0] - 2025-10-26
- Controle du host lors de la redirection http vers https
- Ajout Redirection permanente directement depuis le yaml
- Ajout d'un firewall
  - Rate limiter
  - Antibot
  - Pattern filtering
- Fix: Le hostname n'était pas transféré au backend
- Fix: message context close
- Ajout d'un logger (fichier et syslog)
- Ajout d'un builder docker
- Possibilité d'utiliser ACME en local via pebble pour faire des tests

## [1.0.0] - 2025-09-09

### Ajouté
- Makefile
- Dockerfile
- Tests unitaires et d'intégration
- Documentation
- Version initiale de hnProxy
- Reverse proxy HTTP/HTTPS basique
- Configuration YAML
- Support ACME/Let's Encrypt
- Load balancing round-robin

### Notes
- Première release stable
- Prêt pour la production
- Support multi-plateforme (Linux, macOS, Windows)
