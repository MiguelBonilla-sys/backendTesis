# Solución de Monitoreo para tu Backend

## 🎯 Componentes Agregados

### 1. **phpMyAdmin** (Puerto 8080)
- URL: http://localhost:8080
- Usuario: `postgres`
- Contraseña: `postgres`
- Gestión visual de tu BD PostgreSQL
- Interfaz tipo "phpmyadmin" pero para PostgreSQL

### 2. **Adminer** (Puerto 8081)
- URL: http://localhost:8081
- Alternativa ligera para gestionar múltiples BD
- Soporta: PostgreSQL, MySQL, SQLite, etc.
- Sin necesidad de autenticación (acceso directo)

### 3. **Grafana** (Puerto 3000)
- URL: http://localhost:3000
- Usuario: `admin`
- Contraseña: `admin`
- Panel centralizado para:
  - Logs en tiempo real de LlamaStack
  - Logs de todos los contenedores
  - Visualización de tasa de logs por servicio
  - Dashboards personalizables

### 4. **Loki** (Puerto 3100)
- Servidor de logs centralizado
- Agrega logs de todos los contenedores
- Consultable via Grafana
- Almacenamiento persistente

## 📊 Dashboards Pre-configurados

El dashboard "LlamaStack & All Services Monitoring" incluye:
- **Log Rate by Container**: Gráfico de tasa de logs por servicio
- **LlamaStack Logs**: Tabla con logs parseados en JSON de LlamaStack
- **Real-time Logs**: Stream de logs de todos los contenedores en vivo

## 🚀 Cómo Iniciar

```bash
cd C:\Users\migue\OneDrive\Documents\DEVs\TesisDev\backendTesis

# Detenemos los servicios actuales
docker compose -f docker-compose.deps.yml down

# Iniciamos con la nueva configuración
docker compose -f docker-compose.deps.yml up -d
```

## 🔍 Verificación

```bash
# Ver todos los contenedores
docker compose -f docker-compose.deps.yml ps

# Ver logs de un servicio específico
docker compose -f docker-compose.deps.yml logs -f llamastack

# Ver logs de Loki
docker compose -f docker-compose.deps.yml logs -f loki
```

## 📝 Acceso a los Servicios

| Servicio | Puerto | URL | Usuario | Contraseña |
|----------|--------|-----|---------|-----------|
| PostgreSQL | 5432 | postgres://localhost:5432 | postgres | postgres |
| Redis | 6379 | redis://localhost:6379 | - | - |
| Ollama | 11434 | http://localhost:11434 | - | - |
| LlamaStack | 5001 | http://localhost:5001 | - | - |
| Chroma | 8001 | http://localhost:8001 | - | - |
| **phpMyAdmin** | 8080 | http://localhost:8080 | postgres | postgres |
| **Adminer** | 8081 | http://localhost:8081 | postgres | postgres |
| **Grafana** | 3000 | http://localhost:3000 | admin | admin |
| **Loki** | 3100 | http://localhost:3100 | - | - |

## ⚙️ Configuración de Logs

Cada contenedor ahora envía logs a Loki con:
- `loki-url`: http://localhost:3100/loki/api/v1/push
- Tamaño de batch: 400 líneas
- Labels automáticas: `container_name`, `service_name`, etc.

## 💡 Próximos Pasos

1. **Personalizar dashboards**: Accede a Grafana y crea alertas
2. **Agregar más métricas**: Configura Prometheus si necesitas métricas de sistema
3. **Retención de logs**: Ajusta la configuración en `loki-config.yml`
4. **Backups**: Añade Portainer para gestión visual de contenedores

## 🔧 Troubleshooting

### Error: `logging plugin loki: plugin "loki" not found`
Si al ejecutar `docker compose up` obtienes este error, significa que el driver de logs de Loki no está instalado en tu instancia local de Docker.

**Solución rápida (Windows/Linux/macOS):**
```bash
docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions
```

### Si Loki no recibe logs:
```bash
# Reinicia los servicios para que intenten reconectar el driver
docker compose -f docker-compose.deps.yml restart
```

Si phpMyAdmin no conecta a PostgreSQL:
- Verifica que PostgreSQL está en la misma red
- Usa `postgres` como hostname (no localhost)
- Contraseña: `postgres`
