#!/bin/bash

# Configurables
DOCKERHUB_USER="nicolasalv3"
IMAGE_NAME="rayuela-backend"
TAG="latest"  # podés cambiarlo por `v1.0`, `$(date +%Y%m%d%H%M)`, etc.

# Construir la imagen local
echo "🛠️  Construyendo imagen local..."
docker build -t $IMAGE_NAME:$TAG .

# Etiquetar para Docker Hub
echo "🏷️  Taggeando imagen como $DOCKERHUB_USER/$IMAGE_NAME:$TAG..."
docker tag $IMAGE_NAME:$TAG $DOCKERHUB_USER/$IMAGE_NAME:$TAG

# Login a Docker Hub
echo "🔐  Iniciando sesión en Docker Hub..."
docker login || { echo "❌ Error de login"; exit 1; }

# Pushear la imagen
echo "🚀  Pusheando imagen a Docker Hub..."
docker push $DOCKERHUB_USER/$IMAGE_NAME:$TAG || { echo "❌ Error al pushear"; exit 1; }

echo "✅ Imagen pusheada con éxito: https://hub.docker.com/r/$DOCKERHUB_USER/$IMAGE_NAME"
