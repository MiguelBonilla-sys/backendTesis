FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY requirements.txt .
RUN grep -v pywin32 requirements.txt > requirements_docker.txt && \
    uv pip install --system -r requirements_docker.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]