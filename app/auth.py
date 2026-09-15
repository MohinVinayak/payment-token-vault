from datetime import datetime, timedelta, UTC

import jwt
import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_MINUTES


security = HTTPBearer()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (auto-generates random salt)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Check if a plain password matches the stored hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(username: str, role: str) -> str:
    """Create a signed JWT with username, role, and expiry."""
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(UTC) + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises HTTPException on failure."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """FastAPI dependency — extracts the current user from the JWT in the Authorization header."""
    return decode_token(credentials.credentials)
