import os
from dotenv import load_dotenv

load_dotenv()

# Encryption
FERNET_KEY = os.environ["FERNET_KEY"].strip().encode()
HMAC_SECRET = os.environ["HMAC_SECRET"].strip().encode()

# JWT
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production").strip()
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256").strip()
JWT_EXPIRY_MINUTES = int(os.environ.get("JWT_EXPIRY_MINUTES", "30"))

# Token settings
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "24"))