#!/bin/bash
# autodeploy.sh - Watchdog para revisar cambios cada 45 minutos

PROJECT_DIR="/home/mangel/Documentos/devs/backendTesis"
BRANCH="feat/phase-5-api-layer" # Cambia esto a 'main' si lo fusionas después

cd $PROJECT_DIR || exit 1

while true; do
    echo "[$(date)] Revisando actualizaciones en Git (rama $BRANCH)..."
    git fetch origin
    
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/$BRANCH)

    if [ "$LOCAL" != "$REMOTE" ]; then
        echo "[$(date)] ¡Nuevos cambios detectados! ($LOCAL -> $REMOTE)"
        git pull origin $BRANCH
        
        echo "[$(date)] Reconstruyendo y reiniciando contenedores Docker..."
        docker compose up -d --build
    else
        echo "[$(date)] Sin cambios en el repositorio."
    fi

    # Esperar 45 minutos (2700 segundos)
    echo "[$(date)] Durmiendo por 45 minutos..."
    sleep 2700
done
