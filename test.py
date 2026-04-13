import sys
sys.path.insert(0, '/app')
from auth.auth import create_access_token
import httpx
import asyncio

async def test():
    token = create_access_token('test')
    async with httpx.AsyncClient() as client:
        r = await client.post(
            'http://localhost:8000/api/v1/analyze',
            headers={'Authorization': f'Bearer {token}'},
            json={'url': 'https://xn--pple-43d.com', 'source': 'manual'},
            timeout=120.0
        )
        print(r.status_code)
        print(r.text)

asyncio.run(test())
