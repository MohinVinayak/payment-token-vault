# Payment Token Vault

A secure REST API that tokenizes and detokenizes sensitive credit card data (PANs). Instead of storing raw card numbers, applications send them to this vault — it encrypts and stores them securely, returning a safe, non-sensitive token.

## Architecture

```
Client (Swagger UI / any HTTP client)
  │
  │  HTTP + JWT Bearer token
  ▼
┌─────────────────┐
│   main.py       │  API layer — endpoints, rate limiting, auth
│   (FastAPI)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  services.py    │  Business logic — validation, encryption, RBAC
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│ repository.py   │     │  crypto_utils.py │
│ (Data access)   │     │  (Fernet, HMAC,  │
└────────┬────────┘     │   Luhn, masking) │
         │              └──────────────────┘
         ▼
┌─────────────────┐
│    db.py        │  SQLite + schema
│  (vault.db)     │
└─────────────────┘
```

## Features

- **Tokenization** — Validates card (Luhn), encrypts (Fernet), returns a random token
- **Detokenization** — Admin-only decryption with mandatory audit logging
- **JWT Authentication** — Register/login, Bearer tokens, bcrypt password hashing
- **Role-Based Access** — Service role can tokenize, only admin can detokenize/revoke
- **Token Expiry & Revocation** — Configurable TTL, admin can revoke tokens
- **Idempotency Keys** — Prevents duplicate tokenizations from network retries
- **Rate Limiting** — In-memory per-IP throttling (30 req/min)
- **Audit Logging** — Every access attempt is logged with timestamp, role, and reason

## Tech Stack

- **FastAPI** — ASGI web framework with auto-generated Swagger docs
- **Fernet** (cryptography library) — AES-128-CBC + HMAC-SHA256 authenticated encryption
- **PyJWT + bcrypt** — JWT token auth and password hashing
- **SQLite** — Lightweight embedded database (swappable via repository pattern)
- **Pytest** — 17 tests covering auth, tokenize, detokenize, revoke, and audit

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/register` | None | Register a new user |
| POST | `/login` | None | Login, get JWT token |
| POST | `/tokenize` | JWT | Encrypt card, get token back |
| POST | `/detokenize` | JWT (admin) | Decrypt card from token |
| POST | `/token/{id}/revoke` | JWT (admin) | Revoke a token |
| GET | `/token/{id}` | JWT | Get masked card info & timestamps |
| GET | `/audit-log` | JWT (admin) | View all access logs |

## Local Setup

1. **Clone and enter the directory:**
   ```powershell
   git clone <your-repo-url>
   cd payment-token-vault
   ```

2. **Set up the virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Environment variables:**
   Copy `.env.example` to `.env` and fill in your keys:
   ```powershell
   copy .env.example .env
   ```

5. **Run the server:**
   ```powershell
   uvicorn app.main:app --reload
   ```

6. **Run tests:**
   ```powershell
   pytest tests/ -v
   ```

7. **API docs:**
   Open `http://127.0.0.1:8000/docs` for the interactive Swagger UI.

## Usage Examples

### Register & Login
```bash
# Register
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin1", "password": "secret", "role": "admin"}'

# Login (returns JWT)
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin1", "password": "secret"}'
```

### Tokenize & Detokenize
```bash
# Tokenize a card
curl -X POST http://localhost:8000/tokenize \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"card_number": "4242424242424242"}'

# Detokenize (admin only)
curl -X POST http://localhost:8000/detokenize \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"token": "<token-from-above>", "reason": "refund"}'
```

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Fernet over raw AES** | Fernet bundles AES + HMAC + IV — authenticated encryption out of the box |
| **HMAC-SHA256 for dedup** | Keyed hash prevents rainbow table attacks on card number hashes |
| **bcrypt for passwords** | Slow hash + random salt — resists brute force |
| **JWT for auth** | Stateless, signed tokens — role can't be faked like a plain header |
| **SQLite + repository pattern** | Simple setup, but swappable to PostgreSQL by changing one file |
| **In-memory rate limiting** | No external dependency; production would use Redis |

## Project Structure

```
payment-token-vault/
├── app/
│   ├── __init__.py
│   ├── main.py            — API endpoints, rate limiting, lifespan
│   ├── auth.py            — JWT creation/verification, bcrypt
│   ├── config.py          — Environment variable loading
│   ├── crypto_utils.py    — Fernet encrypt/decrypt, HMAC, Luhn, masking
│   ├── db.py              — SQLite connection, schema, indexes
│   ├── repository.py      — All database queries
│   └── services.py        — Business logic
├── tests/
│   ├── __init__.py
│   └── test_api.py        — 17 integration tests
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```