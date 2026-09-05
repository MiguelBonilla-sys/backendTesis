FROM python:3.12-slim

WORKDIR /app

# El clasificador ONNX de URL (pirocheto/phishing-url-detection) usa un op
# string_normalizer que exige la locale en_US.UTF-8; python:3.12-slim no la trae.
RUN apt-get update && apt-get install -y --no-install-recommends locales \
    && sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

RUN pip install --no-cache-dir uv

COPY requirements.txt .
RUN grep -v pywin32 requirements.txt > requirements_docker.txt && \
    uv pip install --system -r requirements_docker.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]