# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

## [1.2.0] - dev
- choix du blockmessage, avec 403, 404, 418 ou slowfake
- filtrage des patterns wordpress si on ne l'utilise pas
- filtrage des pays via geoloc en liste authorisé ou non authorisé

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
