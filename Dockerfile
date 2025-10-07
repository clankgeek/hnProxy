# Multi-stage build pour optimiser la taille de l'image finale
FROM golang:1.25-alpine AS builder

# Installer les certificats CA et git
RUN apk add --no-cache ca-certificates git

# Créer un utilisateur non-root
RUN adduser -D -s /bin/sh -u 1001 appuser

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers go mod et sum pour le cache des dépendances
COPY go.mod go.sum ./
RUN go mod download

# Copier le code source
COPY . .

# Build l'application avec optimisations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o hnproxy .

# Stage final avec image minimale
FROM scratch

# Copier les certificats CA depuis le builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copier l'utilisateur depuis le builder  
COPY --from=builder /etc/passwd /etc/passwd

# Copier le binaire
COPY --from=builder /app/hnproxy /hnproxy

# Créer les répertoires nécessaires
# Note: Dans scratch, nous devons créer les répertoires différemment
USER 1001

# Exposer les ports
EXPOSE 80 443

# Point de santé pour les orchestrateurs
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/hnproxy", "-health-check"] || exit 1

# Commande par défaut
ENTRYPOINT ["/hnproxy"]
CMD ["-config", "/config/proxy-config.yaml"]

# Labels pour les métadonnées
LABEL maintainer="your-email@example.com"
LABEL description="hnProxy - Reverse proxy with automatic HTTPS via Let's Encrypt"
LABEL version="1.0.0"