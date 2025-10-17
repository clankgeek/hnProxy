#!/bin/bash

# Builder l'image
docker build -t hnproxy-builder .

# Créer un conteneur (sans le démarrer)
docker create --name temp-builder hnproxy-builder

# Copier le binaire vers l'hôte
docker cp temp-builder:/app/build/hnproxy ./build/

# Nettoyer
docker rm temp-builder