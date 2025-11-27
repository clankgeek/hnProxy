# Reverse Proxy avec HTTPS/ACME

Un reverse proxy moderne en Go avec support HTTPS automatique via Let's Encrypt (ACME) et configuration par fichier YAML.

## Fonctionnalités

-  **Reverse proxy** avec routage par hostname
-  **HTTPS automatique** via Let's Encrypt (ACME)
-  **Load balancing** round-robin
-  **Configuration YAML** flexible
-  **Redirection HTTP→HTTPS** optionnelle
-  **Certificats manuels** ou automatiques
-  **Renouvellement automatique** des certificats
-  **Build multi-plateforme**
-  **Firewall** avec limiteur de connexion et antibot

## Configuration

### Créer la configuration

```bash
make example
```

Cela crée `hnproxy.yaml` :

```yaml
production: true # mode production, n'affiche pas les logs en console
listen: "0.0.0.0:8080"
firewall:
    enabled: true
    blockmessage: forbidden # forbidden, notfound, teapot, slowfake
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
    enabled: true #utiliser cert_file et key_file si vous n'utilisez pas ACME
    email: "admin@example.com"
    domains:
      - "example.com"
      - "www.example.com"
    cache_dir: "./certs"
    directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
  cert_file:
  key_file:

redirection:
  example.com: www.example.com

routes:
  www.example.com:
    backends:
      - "http://127.0.0.1:8080"

logger:
  level: debug #"debug", "info", "warn", "error"
  file:
    enable: true # true pour activer le log en fichier
    path: ./littleblog.log
    maxsize: 100 #Taille max du fichier en Mo
    maxbackups: 1 #Nombre max de fichiers de backup
    maxAge: 30 #Nombre de jours avant suppression
    compress: true #Compresser les anciens logs
  syslog:
    enable: false # true pour activer l'émission vers un serveur syslog
    protocol: udp # "tcp", "udp", vide pour unix socket
    address: 1.2.3.4 # addresse ip du serveur syslog, vide pour unix socket
    tag: monBlogPerso
    priority: 6 # LOG_INFO
```

### Modifier la configuration

1. **Changer l'email** ACME
2. **Mettre vos domaines** réels
3. **Configurer vos backends**
4. **Supprimer `directory_url`** pour la production

## Utilisation

### Compilation

```bash
# construire et démarrer le programme
make run

# Construire le binaire
make build

# Construire un deb
make deb
```



### Compilation avec docker

```bash
./docker-build.sh
```

## Commandes Make disponibles

| Commande | Description |
|----------|-------------|
| `make` | Build le projet (défaut) |
| `make build` | Compiler le binaire |
| `make run` | Build et lancer avec la config |
| `make cross-compile` | Build multi-plateforme |
| `make clean` | Nettoyer les artifacts |
| `make help` | Afficher l'aide complète |

## Modes de fonctionnement

### Firewall

```yaml
firewall:
    enabled: true
    blockmessage: forbidden
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
        wordpressremover: true # check des patterns wordpress
    geolocationfiltering:
        enabled: true
        dbpath: ./GeoLite2-Country.mmdb
        notallowedactionblock: false # true si un pays n'est pas listé dans allowed, il sera bloqué
        allowedCountries:
            - FR
        disallowedCountries:
            - CN
            - RU
```

- blockmessage: choix du type de bloquage
  - forbidden, retourne un code type 403
  - notfound, retourne un code de type 404
  - teapot, retourne un code type 418 et affiche une théière en plein écran au format svg
  - slowfake, retourn un code type 200 et affiche des paragraphes de lorem très lentement 

- Rate limiter en requette par minute
- Antibot avec possibilité de laisser passer les good bots

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

- Certificats automatiques
- Renouvellement automatique
- Challenge HTTP-01
- Ports 80 + 443

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

- Go 1.25+
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

### ACME en local avec pebble

Cloner le repos de pebble
```bash
git clone https://github.com/letsencrypt/pebble
cd pebble
```

Editer docker-compose.yaml et supprimer -strict de command:
Vous pouvez démarrer pebble

```bash
docker-compose up
```

Et utiliser
```yaml
acme:
  directory_url: "https://localhost:14000/dir"
```

## Build multi-plateforme

```bash
# Build toutes les plateformes
make cross-compile
```

Plateformes supportées :
- Linux (amd64, arm64)
- macOS (amd64, arm64) 
- Windows (amd64)

## Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! Ouvrez une issue ou une pull request.

---

**Note** : hnProxy est conçu pour la production. Pour des environnements critiques, considérez des solutions comme nginx, Traefik, ou HAProxy.