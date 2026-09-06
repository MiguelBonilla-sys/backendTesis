FROM python:3.12-slim

# El clasificador ONNX de URL (pirocheto/phishing-url-detection) usa un op
# string_normalizer que exige la locale en_US.UTF-8; python:3.12-slim no la trae.
RUN apt-get update && apt-get install -y --no-install-recommends locales \
    && sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
    HF_HOME=/home/appuser/.cache/huggingface \
    HF_URL_ONNX_PATH=/opt/models/phishing-url-detection/model.onnx

# Usuario no-root para el runtime (SAST: dockerfile.security.missing-user).
RUN useradd --system --create-home --uid 1001 appuser

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY requirements.txt .
RUN grep -v pywin32 requirements.txt > requirements_docker.txt && \
    uv pip install --system -r requirements_docker.txt

# Modelo ONNX bundleado en build (revisión pinneada) — descarga reproducible,
# sin fetch de HF ni volumen de cache en runtime.
RUN python -c "from huggingface_hub import hf_hub_download; \
    hf_hub_download('pirocheto/phishing-url-detection', 'model.onnx', \
    revision='44f3b19f705b52532e0aadf3d0d15dd892b8a2fb', \
    local_dir='/opt/models/phishing-url-detection')" \
    && chown -R appuser:appuser /opt/models

COPY --chown=appuser:appuser . .
RUN mkdir -p "$HF_HOME" && chown -R appuser:appuser "$HF_HOME" /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
