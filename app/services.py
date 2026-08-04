from cryptography.fernet import InvalidToken
from app.config import FERNET_KEY, HMAC_SECRET
from app.crypto_utils import (
    generate_token, encrypt_pan, decrypt_pan,
    normalize, luhn_check,
    mask_pan, hash_pan
)
from app import repository


class VaultError(Exception):
    pass


class TokenDecryptionError(VaultError):
    pass


def tokenize(card_number: str, role: str = "service") -> dict:
    normalized = normalize(card_number)
    if not luhn_check(normalized):
        raise ValueError("Invalid card number")

    pan_hash = hash_pan(normalized, HMAC_SECRET)
    existing = repository.find_by_hash(pan_hash)
    if existing:
        repository.log_event(existing["token"], "token_lookup", role)
        return {
            "token": existing["token"],
            "masked_pan": existing["masked_pan"]
        }

    pan_encrypted = encrypt_pan(normalized, FERNET_KEY)
    masked = mask_pan(normalized)
    token = generate_unique_token()
    repository.insert_token(token=token, pan_encrypted=pan_encrypted, pan_hash=pan_hash, masked_pan=masked)

    repository.log_event(token, "token_created", role)
    return {
        "token": token,
        "masked_pan": masked,
    }


def detokenize(token: str, role: str = "admin", reason: str | None = None) -> dict:
    if role != "admin":
        repository.log_event(
            token,
            "detokenize_denied",
            role,
            reason,
        )
        raise PermissionError("only admin allowed")

    record = repository.fetch_by_token(token)
    if not record:
        raise ValueError("Token not found")

    try:
        pan = decrypt_pan(record["pan_encrypted"], FERNET_KEY)
    except InvalidToken:
        repository.log_event(
            token,
            "detokenize_decryption_error",
            role,
            "Corrupted ciphertext",
        )
        raise TokenDecryptionError("Stored pan could not be decrypted")

    repository.log_detokenize_and_update(
        token,
        role,
        reason,
    )
    return {
        "pan": pan
    }


def get_token_metadata(token: str, role: str = "service") -> dict:
    record = repository.fetch_by_token(token)
    if not record:
        raise ValueError("Token not found")
    return {
        "token": token,
        "masked_pan": record["masked_pan"],
        "created_at": record["created_at"],
        "last_used_at": record["last_used_at"],
    }


def get_audit_log(role: str = "admin") -> list[dict]:
    if role != "admin":
        raise PermissionError("Only admin allowed")
    return repository.fetch_all_audit_logs()


def generate_unique_token() -> str:
    while True:
        token = generate_token()
        if not repository.token_exists(token):
            return token