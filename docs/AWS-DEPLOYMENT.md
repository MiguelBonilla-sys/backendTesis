# AWS Lambda Deployment Guide — BackendTesis

> **Estado**: Investigación / Referencia de arquitectura  
> **Actualizado**: 2026-04-12  
> **Audiencia**: Tesis USB Bogotá 2026 — Detector de Phishing IDN Homograph

---

## Tabla de contenidos

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Mapa de servicios: Docker → AWS](#2-mapa-de-servicios-docker--aws)
3. [Arquitectura objetivo](#3-arquitectura-objetivo)
4. [Estimación de costos](#4-estimación-de-costos)
5. [Decisiones de diseño claves](#5-decisiones-de-diseño-claves)
6. [Requisitos previos](#6-requisitos-previos)
7. [Paso a paso: despliegue con Terraform](#7-paso-a-paso-despliegue-con-terraform)
8. [Adaptaciones necesarias en el código](#8-adaptaciones-necesarias-en-el-código)
9. [Cold starts y performance en Lambda](#9-cold-starts-y-performance-en-lambda)
10. [Alternativas evaluadas](#10-alternativas-evaluadas)
11. [Seguridad](#11-seguridad)
12. [Monitoreo y observabilidad](#12-monitoreo-y-observabilidad)
13. [Limitaciones y riesgos](#13-limitaciones-y-riesgos)
14. [Comparativa: Lambda vs ECS Fargate vs EC2](#14-comparativa-lambda-vs-ecs-fargate-vs-ec2)

---

## 1. Resumen ejecutivo

BackendTesis puede desplegarse en AWS usando **AWS Lambda con imágenes de contenedor** como capa de cómputo principal. Esto elimina la gestión de servidores y permite escalar a cero cuando no hay tráfico, ideal para un proyecto de tesis.

**Costo estimado mensual:**

| Escenario | Costo estimado |
|-----------|---------------|
| Primeros 12 meses (free tier activo) | **$5 – $15 / mes** |
| Después del free tier (tráfico tesis) | **$35 – $55 / mes** |
| Producción con Multi-AZ | **$80 – $120 / mes** |

> **Mayor costo fijo**: NAT Gateway (~$32/mes). Se puede eliminar usando VPC Endpoints.

---

## 2. Mapa de servicios: Docker → AWS

| Servicio local (docker-compose) | Servicio AWS equivalente | Tier / SKU recomendado | Costo estimado/mes |
|--------------------------------|--------------------------|------------------------|-------------------|
| **FastAPI app** (uvicorn, 4 workers) | **AWS Lambda** (imagen de contenedor) | 512 MB RAM, timeout 30 s | ~$0 (free tier) |
| **PostgreSQL 15** | **Amazon RDS PostgreSQL 15** | `db.t3.micro` (free tier 12 m) | $0 → $11.52 |
| **ChromaDB** (vector store) | **pgvector** en RDS PostgreSQL | Extensión nativa en RDS PG15 | $0 (incluido en RDS) |
| **Redis 7** | **ElastiCache Serverless** (Redis-compat) | Serverless (escala a 0-ish) | ~$1 – $3 |
| **LlamaStack + Ollama** (Llama 3.1 8B) | **Amazon Bedrock** (Llama 3 8B Instruct) | On-demand por token | ~$0.50 – $2 |
| **API Gateway** (ninguno local) | **API Gateway HTTP API** | HTTP API tier | ~$0 (free tier) |
| **Nginx / reverse proxy** | **CloudFront** (opcional) | Standard | ~$0.01/GB |
| **Secretos (.env)** | **AWS Secrets Manager** | $0.40/secreto/mes | ~$2 |

### Nota sobre ChromaDB → pgvector

ChromaDB no existe como servicio administrado en AWS. Las opciones son:

1. **pgvector en RDS** ✅ (recomendado): Extensión de PostgreSQL, costo cero adicional, misma instancia RDS.
2. **Amazon OpenSearch Serverless**: más potente pero ~$24/mes mínimo.
3. **ECS Fargate ejecutando ChromaDB**: posible pero agrega ~$7/mes y complejidad operativa.

La migración de ChromaDB a pgvector requiere cambios en `models/chromadb_client.py` y `agents/rag_retriever.py`.

### Nota sobre LlamaStack/Ollama → Amazon Bedrock

Ollama necesita GPU y no es viable en Lambda ni en instancias pequeñas de EC2 con costo razonable. Opciones:

1. **Amazon Bedrock** ✅ (recomendado): API completamente administrada, compatible con OpenAI SDK. Meta Llama 3 8B Instruct disponible.
2. **ECS Fargate con GPU** (`p2.xlarge`): ~$0.90/hr = ~$648/mes. Demasiado costoso.
3. **Amazon SageMaker Inference** (endpoint bajo demanda): $0.046/hr para `ml.g4dn.xlarge`. ~$33/mes si usa 8 hrs/día.
4. **Mantener LlamaStack en EC2 `t3.medium`** y conectar Lambda via HTTP.

Para la tesis, Bedrock es la opción más simple y barata. Los cambios requeridos están en `agents/llm_agent.py`.

---

## 3. Arquitectura objetivo

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet / Browser                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS
                           ▼
             ┌─────────────────────────┐
             │   API Gateway HTTP API   │  ($1/M req — free tier)
             │   (o Lambda Func. URL)   │
             └────────────┬────────────┘
                          │ AWS_PROXY
                          ▼
             ┌─────────────────────────┐
             │     AWS Lambda          │  (container image, 512 MB)
             │     FastAPI + Mangum    │  (<- Mangum = ASGI adapter)
             └──┬──────┬──────┬───────┘
                │      │      │
      ┌─────────▼─┐  ┌─▼──────▼──────────┐  ┌────────────────────┐
      │  RDS PG15  │  │ ElastiCache Redis  │  │  Amazon Bedrock    │
      │ + pgvector │  │  Serverless        │  │  Llama 3 8B / SDK  │
      │ (privado)  │  │  (privado)         │  │  (via HTTPS)       │
      └───────────┘  └───────────────────┘  └────────────────────┘
                │
      ┌─────────▼──────────┐   ┌──────────────────────┐
      │  Secrets Manager    │   │  CloudWatch Logs      │
      │  (JWT, TI keys)     │   │  + X-Ray (opcional)   │
      └────────────────────┘   └──────────────────────┘
```

**VPC topology:**

```
VPC 10.0.0.0/16
├── Public Subnets (10.0.101.0/24, 10.0.102.0/24)
│   ├── NAT Gateway (outbound para TI APIs externas)
│   └── Internet Gateway
└── Private Subnets (10.0.1.0/24, 10.0.2.0/24)
    ├── Lambda (ENI en cada AZ)
    ├── RDS PostgreSQL
    └── ElastiCache Serverless
```

---

## 4. Estimación de costos

### Precios en `us-east-1` (región más barata), abril 2026

#### 4.1 Lambda

| Métrica | Free tier | Precio después |
|---------|-----------|----------------|
| Solicitudes | 1 M/mes | $0.20/M req |
| Cómputo | 400,000 GB-seg/mes | $0.0000166667/GB-seg |
| **Ejemplo tesis**: 10,000 req/mes × 2 seg × 512 MB | ✅ free tier | ~$0.00 |
| **Ejemplo prod**: 500,000 req/mes × 2 seg × 512 MB | excede free tier | ~$0.09/mes |

> Lambda con imágenes de contenedor no tiene cargo adicional de almacenamiento.

#### 4.2 API Gateway (HTTP API)

| Solicitudes/mes | Costo |
|----------------|-------|
| < 1 M (free tier 12 m) | **$0.00** |
| 1 M – 300 M | $1.00/M |
| **Tesis**: ~10,000 req/mes | **$0.00** |

#### 4.3 RDS PostgreSQL

| SKU | Costo/hora | Costo/mes | Free tier? |
|-----|-----------|-----------|------------|
| `db.t3.micro` | $0.016 | **$11.52** | ✅ 750 h/mes × 12 meses |
| `db.t4g.micro` (Graviton) | $0.016 | **$11.52** | ❌ |
| `db.t3.small` | $0.034 | **$24.48** | ❌ |
| Aurora Serverless v2 mín. | $0.12/ACU-hr × 0.5 ACU | **$43.20** | ❌ |
| **Almacenamiento gp3** | $0.115/GB/mes | **$2.30** (20 GB) | ✅ 20 GB free tier |
| **Backup** | $0.095/GB/mes | ~$0.50 | ✅ igual al tamaño de instancia |

**Recomendación tesis**: `db.t3.micro` → **$0/mes primeros 12 meses**, luego ~$14/mes.

#### 4.4 ElastiCache Serverless

| Componente | Precio | Estimación tesis |
|-----------|--------|-----------------|
| Datos almacenados | $0.125/GB-hr | ~$0.05/mes (< 1 GB) |
| ECPUs | $0.034/ECPU | ~$0.50/mes |
| **Total** | — | **~$1 – $3/mes** |

> No hay free tier para ElastiCache. Alternativa: usar **DynamoDB con TTL** como caché (~$0/mes).

#### 4.5 Amazon Bedrock — Llama 3 8B Instruct

| Modelo | Input | Output | Estimación tesis |
|--------|-------|--------|-----------------|
| Meta Llama 3.1 8B Instruct | $0.22/1M tokens | $0.22/1M tokens | |
| 100 req/día × 1,000 tokens | — | — | **~$0.66/mes** |
| Claude 3 Haiku (alternativa) | $0.25/1M | $1.25/1M | **~$1.50/mes** |

#### 4.6 NAT Gateway (mayor costo fijo)

| Componente | Precio | Estimación tesis |
|-----------|--------|-----------------|
| Horas (1 NAT) | $0.045/hr | **$32.40/mes** |
| Procesamiento de datos | $0.045/GB | ~$0.50/mes |
| **Total** | — | **~$32.90/mes** |

> **Estrategia de ahorro**: Si las APIs de TI (VirusTotal, URLScan) son opcionales, se puede prescindir del NAT Gateway usando solo VPC Endpoints para servicios AWS (Bedrock, Secrets Manager, RDS, ElastiCache). Ahorro: ~$32/mes.

#### 4.7 Secrets Manager

| Secretos | Costo/mes | Estimación tesis (5 secretos) |
|---------|-----------|-------------------------------|
| $0.40/secreto | — | **$2.00/mes** |
| API calls | $0.05/10,000 | **~$0.01/mes** |

#### 4.8 ECR (Elastic Container Registry)

| Componente | Precio | Estimación (imagen ~1 GB) |
|-----------|--------|---------------------------|
| Almacenamiento | $0.10/GB/mes | **$0.10/mes** |
| Transferencia (intra-región) | $0.00 | $0.00 |

#### 4.9 VPC Endpoints (Interface) — alternativa a NAT

| Endpoint | Costo/hr | Costo/mes (2 AZ) |
|---------|---------|-----------------|
| S3 Gateway | $0.00 | **$0.00** |
| Secrets Manager | $0.01/hr | **$14.40/mes** |
| Bedrock | $0.01/hr | **$14.40/mes** |
| ECR API + DKR | $0.01/hr cada uno | **$28.80/mes** |

> Usar VPC Endpoints solo tiene sentido si el tráfico hacia esos servicios es alto. Para tráfico bajo de tesis, el NAT Gateway es más económico total.

---

### Resumen total mensual

#### Escenario A: Tesis (primeros 12 meses, free tier)

| Servicio | Costo/mes |
|---------|-----------|
| Lambda | $0 (free tier) |
| API Gateway | $0 (free tier) |
| RDS `db.t3.micro` | $0 (free tier) + $2.30 storage |
| ElastiCache Serverless | $2.00 |
| Bedrock Llama 3 8B | $0.70 |
| NAT Gateway | $32.40 |
| Secrets Manager | $2.00 |
| ECR | $0.10 |
| **TOTAL** | **~$39 / mes** |
| **Sin NAT (solo VPC internas)** | **~$7 / mes** |

#### Escenario B: Tesis (después de 12 meses)

| Servicio | Costo/mes |
|---------|-----------|
| Lambda | $0 (tráfico tesis) |
| API Gateway | $0.01 |
| RDS `db.t3.micro` | $13.82 |
| ElastiCache Serverless | $2.00 |
| Bedrock Llama 3 8B | $0.70 |
| NAT Gateway | $32.40 |
| Secrets Manager | $2.00 |
| ECR | $0.10 |
| **TOTAL** | **~$51 / mes** |

#### Escenario C: Producción (Multi-AZ, mayor tráfico)

| Servicio | Costo/mes |
|---------|-----------|
| Lambda (500K req/mes) | $1.00 |
| API Gateway | $0.50 |
| RDS `db.t3.small` Multi-AZ | $48.96 |
| ElastiCache `cache.t3.micro` | $12.24 |
| Bedrock Llama 3 8B | $5.00 |
| NAT Gateway ×2 AZ | $64.80 |
| Secrets Manager | $2.00 |
| CloudWatch Logs | $2.00 |
| **TOTAL** | **~$136 / mes** |

---

## 5. Decisiones de diseño claves

### 5.1 ¿Por qué Lambda sobre ECS Fargate?

| Criterio | Lambda | ECS Fargate |
|---------|--------|-------------|
| Costo base sin tráfico | **$0** | ~$7–15/mes (mínimo) |
| Escalado a cero | ✅ | ❌ (tarea siempre activa) |
| Cold start con imagen grande | ~2–10 s (con Provisioned Concurrency: ~0.5 s) | No aplica |
| Máximo tiempo de ejecución | 15 min | Sin límite |
| Compatibilidad con FastAPI | ✅ via Mangum | ✅ nativo |
| **Veredicto tesis** | ✅ **Preferido** | Solo si latencia < 1 s es crítica |

### 5.2 ¿Por qué imágenes de contenedor y no ZIP?

El proyecto tiene dependencias nativas (`asyncpg`, `chromadb`, `shap`, `onnxruntime`) que superan fácilmente el límite de 250 MB para deployment packages ZIP. Las imágenes de contenedor soportan hasta **10 GB**.

### 5.3 ¿Por qué pgvector en lugar de ChromaDB?

- ChromaDB no existe como servicio administrado en AWS.
- pgvector es una extensión nativa de PostgreSQL 15 disponible en RDS sin costo adicional.
- Elimina la necesidad de un servicio extra (ChromaDB en ECS Fargate).
- La API de pgvector es compatible con embeddings de dimensión fija (e.g., 384 para all-MiniLM).

### 5.4 ¿Por qué Bedrock en lugar de LlamaStack/Ollama?

- Ollama requiere GPU. Las instancias con GPU en AWS son mínimo ~$0.52/hr (`g4dn.xlarge`).
- Amazon Bedrock ofrece **Meta Llama 3.1 8B Instruct** como API sin servidor, pagando solo por tokens.
- El cambio en el código es mínimo: reemplazar el endpoint HTTP de LlamaStack por el SDK de Bedrock.

---

## 6. Requisitos previos

```bash
# Herramientas requeridas
aws --version          # AWS CLI v2
terraform --version    # >= 1.6
docker --version       # >= 24.0
```

Configurar credenciales AWS:

```bash
aws configure
# AWS Access Key ID: <tu-access-key>
# AWS Secret Access Key: <tu-secret-key>
# Default region name: us-east-1
# Default output format: json
```

---

## 7. Paso a paso: despliegue con Terraform

### 7.1 Construir y publicar imagen Docker

```bash
# 1. Autenticar en ECR (reemplazar ACCOUNT y REGION)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$REGION.amazonaws.com

# 2. Crear repositorio ECR (solo la primera vez — Terraform lo hace también)
aws ecr create-repository --repository-name backendtesis-development --region $REGION

# 3. Construir imagen Lambda
docker build -f infra/aws/Dockerfile.lambda \
  -t $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/backendtesis-development:latest .

# 4. Publicar imagen
docker push $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/backendtesis-development:latest
```

### 7.2 Inicializar y aplicar Terraform

```bash
cd infra/aws/terraform

# Inicializar providers
terraform init

# Revisar plan (sin aplicar cambios)
terraform plan \
  -var="lambda_image_uri=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/backendtesis-development:latest" \
  -var="db_password=TuPasswordSeguro123!" \
  -var="secret_key=$(openssl rand -hex 32)"

# Aplicar infraestructura (~5–10 minutos)
terraform apply \
  -var="lambda_image_uri=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/backendtesis-development:latest" \
  -var="db_password=TuPasswordSeguro123!" \
  -var="secret_key=$(openssl rand -hex 32)" \
  -auto-approve
```

### 7.3 Ejecutar migraciones de base de datos

Después de crear la infraestructura, ejecutar las migraciones de Alembic una sola vez:

```bash
# Opción A: Lambda invoke para ejecutar migraciones
aws lambda invoke \
  --function-name backendtesis-development \
  --payload '{"httpMethod": "POST", "path": "/_internal/migrate", "body": ""}' \
  /tmp/response.json

# Opción B: Desde una instancia EC2 bastion en la misma VPC
# Conectar via SSM Session Manager y ejecutar:
#   cd /app && alembic upgrade head
```

**Para pgvector**, habilitar la extensión en PostgreSQL:

```sql
-- Conectar a RDS y ejecutar:
CREATE EXTENSION IF NOT EXISTS vector;
```

### 7.4 Variables de entorno recomendadas (terraform.tfvars)

```hcl
# infra/aws/terraform/terraform.tfvars
# ¡NO COMMITEAR ESTE ARCHIVO! Está en .gitignore.

project_name = "backendtesis"
environment  = "development"
aws_region   = "us-east-1"

# Lambda
lambda_memory_mb       = 512
lambda_timeout_seconds = 30
lambda_image_uri       = "123456789.dkr.ecr.us-east-1.amazonaws.com/backendtesis-development:latest"

# RDS
db_instance_class       = "db.t3.micro"
db_name                 = "phishing_detector"
db_username             = "btadmin"
db_password             = "TuPasswordSeguro123!"  # cambiar

# App
secret_key                   = "clave-aleatoria-32-chars-minimo"
virustotal_api_key           = ""
urlscan_api_key              = ""
google_safe_browsing_api_key = ""
whoisxml_api_key             = ""

# LLM
llamastack_url   = ""  # vacío = Bedrock (requiere cambios en llm_agent.py)
llamastack_model = "meta.llama3-8b-instruct-v1:0"
```

> Agregar `terraform.tfvars` al `.gitignore` del repo.

### 7.5 Destruir infraestructura (ahorro de costos)

```bash
# Eliminar todo cuando no se use
terraform destroy \
  -var="lambda_image_uri=..." \
  -var="db_password=..." \
  -var="secret_key=..." \
  -auto-approve
```

---

## 8. Adaptaciones necesarias en el código

### 8.1 Mangum (ya incluido en `infra/aws/lambda_handler.py`)

```python
# infra/aws/lambda_handler.py — ya creado
from mangum import Mangum
from main import app
handler = Mangum(app, lifespan="auto")
```

Agregar Mangum a requirements:

```bash
pip install "mangum>=0.17"
echo "mangum>=0.17" >> requirements.txt
```

### 8.2 ElastiCache con TLS

ElastiCache Serverless siempre usa TLS (`rediss://`). Actualizar `REDIS_URL` y asegurarse que `aioredis`/`redis-py` soporte SSL:

```python
# models/redis_client.py — verificar que usa ssl=True o rediss://
REDIS_URL = "rediss://endpoint.cache.amazonaws.com:6379/0"
```

### 8.3 pgvector en lugar de ChromaDB (migración opcional)

Si se reemplaza ChromaDB con pgvector:

```python
# models/pgvector_client.py — nuevo cliente (reemplaza chromadb_client.py)
from sqlalchemy import text
from models.database import async_session

async def similarity_search(embedding: list[float], collection: str, top_k: int = 3):
    async with async_session() as session:
        result = await session.execute(
            text("""
                SELECT content, 1 - (embedding <=> :embedding::vector) AS similarity
                FROM vector_embeddings
                WHERE collection = :collection
                ORDER BY embedding <=> :embedding::vector
                LIMIT :top_k
            """),
            {"embedding": str(embedding), "collection": collection, "top_k": top_k}
        )
        return result.fetchall()
```

### 8.4 Amazon Bedrock en lugar de LlamaStack (migración opcional)

```python
# agents/llm_agent.py — adaptación para Bedrock (reemplaza llamada httpx)
import boto3, json

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

async def _call_bedrock(prompt: str) -> str:
    body = json.dumps({
        "prompt": prompt,
        "max_gen_len": 512,
        "temperature": 0.1,
    })
    response = bedrock.invoke_model(
        modelId="meta.llama3-8b-instruct-v1:0",
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    result = json.loads(response["body"].read())
    return result.get("generation", "")
```

> Para el proyecto de tesis, se puede mantener LlamaStack local para desarrollo y usar Bedrock solo en producción AWS. La variable `LLAMASTACK_URL` vacía puede disparar el uso de Bedrock.

### 8.5 Configuración de Alembic para RDS

Asegurarse que `alembic.ini` y `env.py` leen la DATABASE_URL desde variables de entorno:

```python
# alembic/env.py
import os
config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
```

---

## 9. Cold starts y performance en Lambda

### Problema: cold start con imagen grande

Con una imagen de contenedor de ~1–2 GB y dependencias como ChromaDB/Torch, el cold start puede tomar **8–15 segundos**. Estrategias para mitigar:

| Estrategia | Descripción | Costo adicional |
|-----------|-------------|----------------|
| **Provisioned Concurrency** | Mantiene N instancias "calientes" | $0.015/GB-hr provisionado |
| **Lambda SnapStart** | Solo para Java/Kotlin — no aplica | N/A |
| **Reducir imagen** | Eliminar dependencias no usadas (torch, shap) | $0 |
| **Lazy loading** | Cargar modelos solo cuando se necesitan | $0 |
| **Ping periódico** | EventBridge cada 5 min para mantener tibio | ~$0 |

**Estimación Provisioned Concurrency** (1 instancia, 512 MB):
- $0.015 × 0.5 GB × 720 hrs = **$5.40/mes**

Para la tesis, un EventBridge rule que invoca Lambda cada 5 minutos es suficiente y casi gratuito.

### Optimización de la imagen

```dockerfile
# Reducir imagen eliminando dependencias dev-only:
RUN pip install --target /install --no-cache-dir \
    fastapi uvicorn[standard] asyncpg sqlalchemy alembic \
    aiohttp httpx redis pydantic mangum \
    # NO incluir: torch, shap, chromadb (si se migra a pgvector)
```

Una imagen sin ChromaDB/torch pesa ~300–500 MB y tiene cold starts de ~1–3 segundos.

---

## 10. Alternativas evaluadas

### 10.1 AWS App Runner

- Ventaja: más simple que Lambda, no requiere Mangum, sin cold starts.
- Desventaja: mínimo $10–20/mes (cobra por tiempo activo aunque no haya tráfico).
- **Descartado**: más costoso que Lambda para tráfico bajo.

### 10.2 ECS Fargate (solo FastAPI)

- Ventaja: sin cold starts, más familiar (similar a Docker).
- Desventaja: ~$7–15/mes base (tarea siempre corriendo).
- **Considerado como alternativa** si los cold starts de Lambda son inaceptables.

### 10.3 Elastic Beanstalk

- Ventaja: muy fácil de desplegar.
- Desventaja: EC2 subyacente ($8+/mes para `t3.micro`), más overhead de gestión.
- **Descartado**: no aprovecha serverless.

### 10.4 Aurora Serverless v2

- Ventaja: escala con la carga.
- Desventaja: mínimo 0.5 ACU = ~$0.12/hr = **$43.20/mes**. Demasiado costoso vs `db.t3.micro`.
- **Descartado**: excede el presupuesto de tesis.

### 10.5 DynamoDB como caché (en lugar de ElastiCache)

- Ventaja: free tier 25 GB, sin cargo fijo.
- Desventaja: requiere cambios en `data_pipeline/cache_manager.py`.
- **Viable para tesis**: reemplazar ElastiCache Redis con DynamoDB + TTL ahorra ~$2/mes.

---

## 11. Seguridad

### Principios aplicados en la infraestructura Terraform

1. **Mínimo privilegio IAM**: La Lambda solo tiene permisos para Secrets Manager, CloudWatch Logs, y networking VPC.
2. **RDS privado**: No `publicly_accessible = true`. Solo accesible desde Lambda en la misma VPC.
3. **ElastiCache privado**: Solo en subnets privadas, security group permite solo tráfico desde Lambda.
4. **Secrets Manager**: Contraseñas y API keys nunca en variables de entorno directas; solo ARN del secreto.
5. **ECR scan on push**: Escaneo de vulnerabilidades automático en cada `docker push`.
6. **Cifrado en reposo**: RDS con `storage_encrypted = true`, ECR con KMS.
7. **TLS obligatorio**: ElastiCache Serverless siempre TLS, RDS con SSL disponible.
8. **Deletion protection**: `deletion_protection = true` en RDS para producción.

### Configuración adicional recomendada

```hcl
# Habilitar AWS WAF en API Gateway para producción
# Habilitar CloudTrail para auditoría
# Habilitar AWS Config para compliance
# Usar AWS Shield Standard (gratuito) anti-DDoS básico
```

---

## 12. Monitoreo y observabilidad

### CloudWatch (incluido)

- **Lambda logs**: `/aws/lambda/backendtesis-development`
- **API Gateway logs**: `/aws/apigateway/backendtesis-development`
- **Métricas automáticas**: invocaciones, errores, duración, throttles

### Alarmas recomendadas

```bash
# Alarma de errores Lambda (>5% error rate)
aws cloudwatch put-metric-alarm \
  --alarm-name "backendtesis-lambda-errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --dimensions Name=FunctionName,Value=backendtesis-development \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:alerts
```

### AWS X-Ray (opcional, ~$5/mes para tesis)

```python
# main.py — agregar tracing
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.ext.fastapi.middleware import XRayMiddleware
app.add_middleware(XRayMiddleware, recorder=xray_recorder)
```

---

## 13. Limitaciones y riesgos

| Riesgo | Severidad | Mitigación |
|--------|-----------|------------|
| Cold start > 10 s con imagen grande | Media | Provisioned Concurrency o ping periódico |
| Tiempo máximo Lambda = 15 min | Baja | Los análisis actuales toman < 30 s |
| ChromaDB no disponible como servicio AWS | Media | Migrar a pgvector (ver §8.3) |
| LlamaStack/Ollama requiere GPU cara | Alta | Migrar a Amazon Bedrock (ver §8.4) |
| NAT Gateway costo fijo $32/mes | Media | Usar VPC Endpoints o deshabilitar TI externas en dev |
| ElastiCache sin free tier | Baja | Usar DynamoDB TTL como alternativa (ver §10.5) |
| Lambda en VPC = cold start +3–5 s | Media | Usar Provisioned Concurrency o Function URL sin VPC (sacrifica acceso a RDS privado) |
| Conexiones RDS con Lambda (connection pooling) | Media | Usar RDS Proxy ($0.015/GB/hr) o pgBouncer |

### Problema de connection pooling con Lambda

Lambda puede generar muchas conexiones a RDS si hay muchas instancias concurrentes. Soluciones:

1. **RDS Proxy** (recomendado para prod): ~$0.015/GB/hr = ~$3–10/mes. Reduce conexiones a RDS.
2. **Limitar `reserved_concurrent_executions`**: Por ejemplo, máximo 10 instancias concurrentes.
3. **Usar SQLAlchemy pool_size=1, max_overflow=0** en la Lambda.

---

## 14. Comparativa: Lambda vs ECS Fargate vs EC2

| Característica | **Lambda** | **ECS Fargate** | **EC2 t3.small** |
|---------------|-----------|----------------|-----------------|
| Costo base (sin tráfico) | **$0** | ~$10/mes | ~$15/mes |
| Escala a cero | ✅ | ❌ | ❌ |
| Gestión de SO | ✅ ninguna | ✅ ninguna | ❌ manual |
| Cold start | 2–15 s | <1 s | <1 s |
| Tiempo máx. ejecución | 15 min | ilimitado | ilimitado |
| Workers concurrentes | Auto | Config manual | Manual |
| VPC support | ✅ | ✅ | ✅ |
| Docker nativo | Via ECR | ✅ | ✅ |
| Costo tesis (12 meses) | **~$7–15/mes** | ~$20–30/mes | ~$20–35/mes |
| Costo después | **~$40–55/mes** | ~$40–60/mes | ~$45–70/mes |
| **Recomendación** | ✅ **Tesis** | Producción con SLA | Migración sencilla |

---

## Referencias

- [AWS Lambda Pricing](https://aws.amazon.com/lambda/pricing/)
- [AWS RDS Pricing](https://aws.amazon.com/rds/postgresql/pricing/)
- [ElastiCache Serverless Pricing](https://aws.amazon.com/elasticache/pricing/)
- [API Gateway HTTP API Pricing](https://aws.amazon.com/api-gateway/pricing/)
- [Amazon Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)
- [NAT Gateway Pricing](https://aws.amazon.com/vpc/pricing/)
- [Mangum — ASGI adapter for AWS Lambda](https://mangum.fastapiexpert.com/)
- [pgvector en Amazon RDS](https://aws.amazon.com/about-aws/whats-new/2023/05/amazon-rds-postgresql-pgvector-ml-model-integration/)
- [AWS Pricing Calculator](https://calculator.aws/)
