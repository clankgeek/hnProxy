# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

## [1.3.1] - 2025-10-17
- Ajout d'un builder docker

## [1.3.0] - 2025-10-15
- Ajout d'un logger (fichier et syslog)

## [1.2.1] - 2025-10-14
- FIX: Le hostname n'était pas transféré au backend

## [1.2.0] - 2025-10-07
- Configuration plus fine du firewall dans le fichier yaml

## [1.1.0] - 2025-09-17
- Ajout d'un firewall avec
  - Rate limiter
  - Antibot

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
