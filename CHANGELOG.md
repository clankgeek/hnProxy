# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhère au [Versioning Sémantique](https://semver.org/spec/v2.0.0.html).

### Ajouté
- Support HTTPS automatique via Let's Encrypt (ACME)
- Load balancing round-robin pour les backends
- Configuration via fichier YAML
- Redirection HTTP vers HTTPS optionnelle
- Headers de forwarding (X-Forwarded-*)
- Service systemd pour installation système
- Support Docker avec image optimisée
- Tests unitaires et d'intégration
- Pipeline CI/CD GitHub Actions
- Scripts de build et test automatisés
- Linting et vérifications sécurité
- Documentation

### Sécurité
- Validation stricte des configurations
- Gestion sécurisée des certificats ACME
- Headers de sécurité par défaut

## [1.0.1] - 2025-09-10
- Makefile
- Dockerfile
- Tests unitaires et d'intégration
- Documentation

## [1.0.0] - 2025-09-09

### Ajouté
- Version initiale de hnProxy
- Reverse proxy HTTP/HTTPS basique
- Configuration YAML
- Support ACME/Let's Encrypt
- Load balancing round-robin

### Notes
- Première release stable
- Prêt pour la production
- Support multi-plateforme (Linux, macOS, Windows)
