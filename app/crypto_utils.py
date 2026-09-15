import hmac
import hashlib
import secrets
from cryptography.fernet import Fernet


def generate_token() -> str:
    """Generate a cryptographically secure random token (32 chars, URL-safe)."""
    return secrets.token_urlsafe(24)


def encrypt_pan(card_number: str, key: bytes) -> str:
    """Encrypt a card number using Fernet symmetric encryption."""
    f = Fernet(key)
    encrypted_bytes = f.encrypt(card_number.encode())
    return encrypted_bytes.decode()


def decrypt_pan(ciphertext: str, key: bytes) -> str:
    """Decrypt a Fernet-encrypted card number back to plaintext."""
    f = Fernet(key)
    decrypted_bytes = f.decrypt(ciphertext.encode())
    return decrypted_bytes.decode()


def normalize(card_number: str) -> str:
    """Strip dashes and spaces from a card number."""
    return card_number.replace("-", "").replace(" ", "")


def luhn_check(card_number: str) -> bool:
    """Validate a card number using the Luhn algorithm (mod-10 checksum)."""
    if not card_number.isdigit():
        return False

    reversed_number = card_number[::-1]
    total = 0

    for index, digit in enumerate(reversed_number):
        num = int(digit)
        if index % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num

    return total % 10 == 0


def mask_pan(card_number: str) -> str:
    """Mask all but the last 4 digits of a card number."""
    last_four = card_number[-4:]
    return f"**** **** **** {last_four}"


def hash_pan(card_number: str, username: str, secret: bytes) -> str:
    """Create a keyed HMAC-SHA256 hash (Privacy-First: scoped to the username)."""
    payload = f"{username}:{card_number}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()
