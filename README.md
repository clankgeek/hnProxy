# Reverse Proxy avec HTTPS/ACME

Un reverse proxy moderne en Go avec support HTTPS automatique via Let's Encrypt (ACME) et configuration par fichier YAML.

## ✨ Fonctionnalités

- 🔀 **Reverse proxy** avec routage par hostname
- 🔒 **HTTPS automatique** via Let's Encrypt (ACME)
- ⚖️ **Load balancing** round-robin
- 📝 **Configuration YAML** flexible
- 🔄 **Redirection HTTP→HTTPS** optionnelle
- 📜 **Certificats manuels** ou automatiques
- 🤖 **Renouvellement automatique** des certificats
- 📦 **Build multi-plateforme**
- 🛡️ **Firewall** avec limiteur de connexion et antibot

## 🚀 Installation rapide

```bash
# Setup complet pour nouveaux utilisateurs
make setup

# Ou étape par étape
make deps          # Installer les dépendances
make build         # Compiler
make example       # Créer la config exemple
make run           # Lancer le proxy
```

## 📋 Configuration

### Créer la configuration

```bash
make example
```

Cela crée `proxy-config.yaml` :

```yaml
listen: "0.0.0.0:8080"

firewall:
    enabled: true
    ratelimiter:
        enabled: true
        limit: 100
    antibot:
        enabled: true
        blockLegitimeBots: false
    patternsfiltering:
        enabled: false
    suspiciousbehavior:
        enabled: false

tls:
  enabled: true
  redirect_http: true
  acme:
    email: "admin@example.com"
    domains:
      - "app1.example.com"
      - "api.example.com"
    cache_dir: "./certs"
    directory_url: https://acme-staging-v02.api.letsencrypt.org/directory

routes:
  app1.example.com:
    backends:
      - "http://127.0.0.1:3001"
      - "http://127.0.0.1:3002"
  
  api.example.com:
    backends:
      - "http://127.0.0.1:5001"
```

### Modifier la configuration

1. **Changer l'email** ACME
2. **Mettre vos domaines** réels
3. **Configurer vos backends**
4. **Supprimer `directory_url`** pour la production

## 🏃 Utilisation

### Développement

```bash
# Lancer en mode dev
make dev

# Watch mode avec auto-reload (nécessite 'entr')
make watch
```

### Production

```bash
# Build et run
make run

# Ou installer système
make install
hnproxy -config /path/to/config.yaml
```

### Service système

```bash
# Créer service systemd
make systemd

# Démarrer le service
sudo systemctl enable hnproxy
sudo systemctl start hnproxy
sudo systemctl status hnproxy
```

## 🔧 Commandes Make disponibles

| Commande | Description |
|----------|-------------|
| `make` | Build le projet (défaut) |
| `make setup` | Setup complet pour nouveaux utilisateurs |
| `make build` | Compiler le binaire |
| `make run` | Build et lancer avec la config |
| `make dev` | Mode développement |
| `make example` | Créer config exemple |
| `make install` | Installer dans le système |
| `make systemd` | Créer service systemd |
| `make cross-compile` | Build multi-plateforme |
| `make release` | Créer archives de release |
| `make clean` | Nettoyer les artifacts |
| `make help` | Afficher l'aide complète |

## 🌐 Modes de fonctionnement

### Firewall

```yaml
firewall:
    ratelimiter:
        enabled: true
        limit: 100
    antibot:
        enabled: true
        blockLegitimeBots: false
```

- ✅ Rate limiter en requette par minute
- ✅ Antibot avec possibilité de laisser passer les good bots

### ACME/Let's Encrypt (Recommandé)

```yaml
tls:
  enabled: true
  redirect_http: true
  acme:
    email: "admin@example.com"
    domains: ["app.example.com"]
    cache_dir: "./certs"
```

- ✅ Certificats automatiques
- ✅ Renouvellement automatique
- ✅ Challenge HTTP-01
- ✅ Ports 80 + 443

### Certificats manuels

```yaml
tls:
  enabled: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
```

### HTTP simple

```yaml
listen: "0.0.0.0:8080"
# Pas de section TLS
```

## 🔍 Prérequis

### Système

```bash
# Vérifier les prérequis
make check
```

- Go 1.19+
- Ports 80 et 443 libres (pour HTTPS)
- Privilèges root (pour ports < 1024)
- DNS configuré (domaines → votre IP)

### Réseau

- **Port 80** : Challenges ACME et redirection HTTP
- **Port 443** : Trafic HTTPS
- **Firewall** : Ouvrir ports 80/443
- **DNS** : A/AAAA records vers votre serveur

## 🧪 Test

### Local avec hosts

```bash
# Modifier /etc/hosts
echo "127.0.0.1 app1.local api.local" >> /etc/hosts

# Tester
curl http://app1.local:8080/
```

### ACME Staging

Pour tester sans limites Let's Encrypt :

```yaml
acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
```

## 🏗️ Build multi-plateforme

```bash
# Build toutes les plateformes
make cross-compile

# Créer archives de release
make release
```

Plateformes supportées :
- Linux (amd64, arm64)
- macOS (amd64, arm64) 
- Windows (amd64)

## 📊 Monitoring

### Logs

```bash
# Service systemd
sudo journalctl -u hnproxy -f

# Direct
sudo ./hnproxy -config config.yaml
```

### Status

```bash
# Vérifier le service
sudo systemctl status hnproxy

# Certificats ACME
ls -la ./certs/
```

## ❓ Dépannage

### Port déjà utilisé

```bash
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443
```

### Certificats ACME

```bash
# Vider le cache et recommencer
rm -rf ./certs/
sudo systemctl restart hnproxy
```

### DNS

```bash
# Vérifier la résolution
nslookup app1.example.com
dig app1.example.com
```

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! Ouvrez une issue ou une pull request.

---

**Note** : hnProxy est conçu pour la production. Pour des environnements critiques, considérez des solutions comme nginx, Traefik, ou HAProxy.