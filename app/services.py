import json
from datetime import datetime, timedelta, UTC

from cryptography.fernet import InvalidToken

from app.config import FERNET_KEY, HMAC_SECRET, TOKEN_TTL_HOURS
from app.crypto_utils import (
    generate_token, encrypt_pan, decrypt_pan,
    normalize, luhn_check,
    mask_pan, hash_pan,
)
from app.auth import hash_password, verify_password, create_token as create_jwt
from app import repository


class VaultError(Exception):
    pass


class TokenDecryptionError(VaultError):
    pass


# ── Auth ───────────────────────────────────────────────

def register(username: str, password: str, role: str = "service") -> dict:
    """Register a new user with a hashed password."""
    if role == "admin":
        raise PermissionError("Admin accounts cannot be self-registered")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(c.isalpha() for c in password):
        raise ValueError("Password must contain at least one letter")

    if repository.find_user(username):
        raise ValueError("Username already exists")

    password_hash = hash_password(password)
    repository.create_user(username, password_hash, role)
    return {"message": f"User '{username}' registered successfully"}


def login(username: str, password: str) -> dict:
    """Verify credentials and return a JWT token."""
    user = repository.find_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        raise ValueError("Invalid username or password")

    token = create_jwt(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer"}


# ── Tokenize ───────────────────────────────────────────

def tokenize(
    card_number: str,
    username: str,
    role: str = "service",
    idempotency_key: str | None = None,
) -> dict:
    """Validate, encrypt, and tokenize a card number, isolated per user."""

    # Check idempotency — return cached response if we've seen this key
    if idempotency_key:
        cached = repository.find_idempotency(idempotency_key)
        if cached:
            return json.loads(cached["response"])

    normalized = normalize(card_number)
    if not luhn_check(normalized):
        raise ValueError("Invalid card number")

    # Dedup — check if this card was already tokenized by THIS user
    pan_hash = hash_pan(normalized, HMAC_SECRET)
    existing = repository.find_by_user_and_hash(username, pan_hash)
    if existing:
        repository.log_event(existing["token"], "token_lookup", role)
        result = {
            "token": existing["token"],
            "masked_pan": existing["masked_pan"],
        }
        if idempotency_key:
            repository.insert_idempotency(idempotency_key, result)
        return result

    # Encrypt and store
    pan_encrypted = encrypt_pan(normalized, FERNET_KEY)
    masked = mask_pan(normalized)
    token = generate_unique_token()
    expires_at = (datetime.now(UTC) + timedelta(hours=TOKEN_TTL_HOURS)).isoformat()

    repository.insert_token(
        token=token,
        username=username,
        pan_encrypted=pan_encrypted,
        pan_hash=pan_hash,
        masked_pan=masked,
        expires_at=expires_at,
    )
    repository.log_event(token, "token_created", role)

    result = {"token": token, "masked_pan": masked}

    if idempotency_key:
        repository.insert_idempotency(idempotency_key, result)

    return result


# ── Detokenize ─────────────────────────────────────────

def detokenize(
    token: str, role: str = "admin", reason: str | None = None
) -> dict:
    """Decrypt and return the original card number (admin only)."""
    if role != "admin":
        repository.log_event(token, "detokenize_denied", role, reason)
        raise PermissionError("Only admin role is allowed to detokenize")

    record = repository.fetch_by_token(token)
    if not record:
        raise ValueError("Token not found")

    # Check if token is revoked
    if record["is_revoked"]:
        repository.log_event(token, "detokenize_revoked", role, reason)
        raise ValueError("Token has been revoked")

    # Check if token has expired
    if record["expires_at"]:
        expires_at = datetime.fromisoformat(record["expires_at"])
        if expires_at < datetime.now(UTC):
            repository.log_event(token, "detokenize_expired", role, reason)
            raise ValueError("Token has expired")

    try:
        pan = decrypt_pan(record["pan_encrypted"], FERNET_KEY)
    except InvalidToken:
        repository.log_event(token, "detokenize_decryption_error", role, "Corrupted ciphertext")
        raise TokenDecryptionError("Stored PAN could not be decrypted")

    repository.log_detokenize_and_update(token, role, reason)
    return {"pan": pan}


# ── Revoke ─────────────────────────────────────────────

def revoke_token(token: str, role: str = "admin") -> dict:
    """Revoke a token so it can no longer be detokenized."""
    if role != "admin":
        raise PermissionError("Only admin role is allowed to revoke tokens")

    record = repository.fetch_by_token(token)
    if not record:
        raise ValueError("Token not found")

    repository.revoke_token(token)
    repository.log_event(token, "token_revoked", role)
    return {"message": "Token revoked successfully"}


# ── Metadata & Audit ───────────────────────────────────

def get_token_metadata(token: str, role: str = "service") -> dict:
    """Return non-sensitive metadata about a token."""
    record = repository.fetch_by_token(token)
    if not record:
        raise ValueError("Token not found")
    return {
        "token": token,
        "masked_pan": record["masked_pan"],
        "created_at": record["created_at"],
        "last_used_at": record["last_used_at"],
        "expires_at": record["expires_at"],
        "is_revoked": bool(record["is_revoked"]),
    }


def get_audit_log(role: str = "admin") -> list[dict]:
    """Return all audit log entries (admin only)."""
    if role != "admin":
        raise PermissionError("Only admin role is allowed to view audit logs")
    return repository.fetch_all_audit_logs()


# ── Helpers ────────────────────────────────────────────

def generate_unique_token() -> str:
    """Generate tokens until we get one that doesn't already exist."""
    while True:
        token = generate_token()
        if not repository.token_exists(token):
            return token