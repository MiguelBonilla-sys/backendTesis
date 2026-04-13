import jwt, os
from datetime import datetime, timedelta

encoded_jwt = jwt.encode({"sub": "admin", "exp": datetime.utcnow() + timedelta(days=1)}, "changeme-use-strong-secret-in-production", algorithm="HS256")
print(encoded_jwt)
