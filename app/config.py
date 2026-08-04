import os
from dotenv import load_dotenv

load_dotenv()

FERNET_KEY = os.environ["FERNET_KEY"].encode()
HMAC_SECRET = os.environ["HMAC_SECRET"].encode()