# Deploying BackendTesis on Dokploy

This guide walks you through deploying the full BackendTesis stack
(FastAPI + PostgreSQL + Redis + ChromaDB + Ollama + LlamaStack)
on your own VPS using **[Dokploy](https://dokploy.com)** — an open-source,
self-hosted PaaS built on Docker Compose and Traefik.

---

## Table of Contents

1. [Server Requirements](#1-server-requirements)
2. [Install Dokploy on the VPS](#2-install-dokploy-on-the-vps)
3. [Point Your Domain to the VPS](#3-point-your-domain-to-the-vps)
4. [Create a Compose Project in Dokploy](#4-create-a-compose-project-in-dokploy)
5. [Set Environment Variables](#5-set-environment-variables)
6. [Deploy the Stack](#6-deploy-the-stack)
7. [Pull the Ollama Model (post-deploy)](#7-pull-the-ollama-model-post-deploy)
8. [Verify the Deployment](#8-verify-the-deployment)
9. [GPU Support (optional)](#9-gpu-support-optional)
10. [Useful Dokploy Commands](#10-useful-dokploy-commands)

---

## 1. Server Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 vCores | 8+ vCores |
| RAM | 16 GB | 32 GB (Ollama CPU mode) |
| Disk | 60 GB SSD | 120 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Open ports | 22, 80, 443 | 22, 80, 443 |

> **Note — Ollama RAM:** `llama3.1:8b` (GGUF Q4) needs ~6 GB RAM for
> the model alone. With all other services running, 16 GB is the absolute
> minimum; 32 GB gives comfortable headroom on CPU-only servers.
>
> If the VPS has an **NVIDIA GPU** (≥ 8 GB VRAM), inference is much faster.
> See [Section 9](#9-gpu-support-optional) for the GPU compose snippet.

---

## 2. Install Dokploy on the VPS

SSH into your fresh Ubuntu 22.04 VPS as **root** (or a sudoer):

```bash
ssh root@<your-vps-ip>
```

Run the official one-liner installer:

```bash
curl -sSL https://dokploy.com/install.sh | sh
```

The installer will:
- Install Docker + Docker Compose v2
- Pull and start Dokploy itself (running on port **3000**)
- Create the shared `dokploy-network` Traefik network
- Print a temporary admin password

Open `http://<your-vps-ip>:3000` in your browser, log in with the printed
credentials, and **immediately change the password** in Settings → Security.

---

## 3. Point Your Domain to the VPS

Create two DNS `A` records pointing to your VPS IP:

| Name | Type | Value |
|------|------|-------|
| `api.yourdomain.com` | A | `<vps-ip>` |
| `*.yourdomain.com` *(optional wildcard)* | A | `<vps-ip>` |

Wait for DNS propagation (usually a few minutes with most registrars).

---

## 4. Create a Compose Project in Dokploy

1. Log into the Dokploy dashboard (`http://<your-vps-ip>:3000`).
2. Click **Create Project** → give it a name, e.g. `backend-tesis`.
3. Inside the project, click **Create Service** → choose **Compose**.
4. Under **Source**, select **Git** and paste:
   ```
   https://github.com/MiguelBonilla-sys/backendTesis
   ```
5. Set the **Branch** to `main` (or your production branch).
6. Set the **Compose File** path to:
   ```
   docker-compose.dokploy.yml
   ```
7. Click **Save**.

---

## 5. Set Environment Variables

In the Compose service page, click the **Environment** tab and add the
following variables. Dokploy injects these at build/run time — they are
**never stored in the repository**.

### Required

| Variable | Example Value | Notes |
|----------|---------------|-------|
| `DOMAIN` | `api.yourdomain.com` | Must match the DNS record from Step 3 |
| `SECRET_KEY` | `$(openssl rand -hex 32)` | Generate with the command shown |
| `POSTGRES_PASSWORD` | `S0m3Str0ngP4ss!` | Use a strong password |

### Optional (defaults work for most setups)

| Variable | Default | Notes |
|----------|---------|-------|
| `POSTGRES_USER` | `postgres` | |
| `POSTGRES_DB` | `phishing_detector` | |
| `LLAMASTACK_MODEL` | `ollama/Llama-3.1-8B-Instruct-GGUF` | LlamaStack model ID (see note below) |
| `CORS_ORIGINS` | `[]` | JSON array: `["https://app.yourdomain.com"]` |

### Threat Intelligence API Keys (leave blank to skip that source)

| Variable | Where to get it |
|----------|----------------|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| `URLSCAN_API_KEY` | https://urlscan.io/user/profile/ |
| `GOOGLE_SAFE_BROWSING_API_KEY` | https://console.cloud.google.com |
| `WHOISXML_API_KEY` | https://whoisxmlapi.com |

> **Generate a strong SECRET_KEY** on your local machine or in any shell:
> ```bash
> openssl rand -hex 32
> ```

> **`LLAMASTACK_MODEL` vs Ollama tag:** `LLAMASTACK_MODEL` uses LlamaStack's
> internal `provider/model-name` format (e.g. `ollama/Llama-3.1-8B-Instruct-GGUF`).
> The Ollama model you pull in Step 7 uses Ollama's own tag format (`llama3.1:8b`).
> Both refer to the same weights — they are just different naming conventions
> used by the two different tools.

---

## 6. Deploy the Stack

1. In the Dokploy compose service page, click **Deploy**.
2. Dokploy will clone the repo, build the `Dockerfile`, pull all other
   images, and start every service in the correct dependency order.
3. Watch the **Logs** tab — the build takes 3–10 minutes on a fresh server
   (downloading Ollama/LlamaStack images is the slow part).

Once all containers are green, Traefik automatically issues a Let's Encrypt
certificate for `${DOMAIN}`.

---

## 7. Pull the Ollama Model (post-deploy)

After the stack is running, the Ollama container needs the model weights.
Run this once via Dokploy's **Terminal** tab for the `bt-ollama` service,
or SSH into the VPS and exec into the container:

```bash
# Option A — Dokploy Terminal tab (select bt-ollama container)
ollama pull llama3.1:8b

# Option B — from VPS SSH
docker exec -it bt-ollama ollama pull llama3.1:8b
```

> **Model naming note:** `llama3.1:8b` is the Ollama tag used to pull/run the
> model locally inside the Ollama container.  The `LLAMASTACK_MODEL` env var
> (`ollama/Llama-3.1-8B-Instruct-GGUF`) is a separate LlamaStack model ID
> that tells LlamaStack which Ollama-backed model to use — both refer to the
> same weights.

> **Disk space:** `llama3.1:8b` (Q4_K_M) is ~4.9 GB. Make sure your disk
> has enough free space before pulling.

The download takes 5–15 minutes depending on the server's bandwidth.
When finished, verify it is listed:

```bash
docker exec bt-ollama ollama list
```

Expected output:
```
NAME                    ID              SIZE    MODIFIED
llama3.1:8b             ...             4.9 GB  a few seconds ago
```

---

## 8. Verify the Deployment

### Health endpoint

```bash
curl https://api.yourdomain.com/health
```

Expected response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "components": {
    "api": "ok",
    "database": "ok",
    "redis": "ok",
    "chromadb": "ok",
    "llamastack": "ok"
  }
}
```

### Interactive docs

Open `https://api.yourdomain.com/docs` in your browser to access the
Swagger UI and test the `/analyze` endpoint interactively.

### Readiness probe

```bash
curl https://api.yourdomain.com/ready
# → {"ready": true}
```

---

## 9. GPU Support (optional)

If the VPS has an NVIDIA GPU, uncomment the `deploy.resources` block in
`docker-compose.dokploy.yml` for the `ollama` service:

```yaml
  ollama:
    image: ollama/ollama:latest
    # ...
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

Also install the NVIDIA Container Toolkit on the host **before** deploying:

```bash
# Ubuntu 22.04
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

---

## 10. Useful Dokploy Commands

All of these can also be run from Dokploy's **Terminal** tab.

```bash
# View real-time app logs
docker logs -f bt-api

# Restart only the API without redeploying everything
docker restart bt-api

# Open a shell inside the API container
docker exec -it bt-api bash

# Check all container statuses
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Scale the API to 2 replicas (if you remove container_name first)
docker compose -f docker-compose.dokploy.yml up -d --scale app=2
```

---

## Architecture Overview

```
Internet
   │  HTTPS (443)
   ▼
┌──────────────────────────┐
│   Traefik  (Dokploy)     │  ← automatic Let's Encrypt TLS
│   dokploy-network        │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐   bt-internal network (private)
│   bt-api  (FastAPI)      │──────────────────────────────────┐
│   port 8000              │                                  │
└──────────────────────────┘                                  │
                                                              │
          ┌──────────────────────────────────────────────────┐│
          │  bt-postgres  bt-redis  bt-chroma                ││
          │  bt-ollama    bt-llamastack                      ││
          └──────────────────────────────────────────────────┘│
          ◄────────────────────────────────────────────────────┘
                  No ports exposed to host/internet
```

Only the `bt-api` service is attached to both networks.
All other services live exclusively on `bt-internal` and are
**not reachable from the public internet**.
