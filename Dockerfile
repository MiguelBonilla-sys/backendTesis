FROM python:3.11-slim

WORKDIR /app

# Copiamos primero solo los requerimientos para aprovechar el caché de capas
COPY requirements_docker.txt .

# Preinstalamos PyTorch CPU-only para evitar bajar dependencias CUDA gigantes.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.3.1+cpu

# Instalamos el resto de dependencias, excluyendo paquetes no usados por este backend.
RUN awk '!/^llama-stack==/ && !/^llama-stack-api==/' requirements_docker.txt > requirements_runtime.txt \
	&& pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements_runtime.txt

# NOTA: No copiamos tu código fuente (COPY . .) intencionalmente. 
# El código se inyectará dinámicamente llamando a la ruta del host (bind mount) 
# en el docker-compose.yml para ahorrar almacenamiento y permitirte 
# editar los archivos de Python sin reconstruir la imagen.
