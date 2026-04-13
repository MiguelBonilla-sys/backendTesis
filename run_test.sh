#!/bin/bash
export TOKEN=$(docker compose exec -T app bash -c "python -W ignore -c \"import sys; sys.path.insert(0, '/app'); from auth.auth import create_access_token; print(create_access_token('test'))\"" | tr -d '\r\n')
echo "Token gen: ${TOKEN:0:15}..."
curl -s -X POST http://localhost:8000/api/v1/analyze -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"url":"https://xn--pple-43d.com","source":"manual"}' | jq
