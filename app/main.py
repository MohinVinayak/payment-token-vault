import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import services
from app.auth import get_current_user
from app.db import init_db
from app.services import TokenDecryptionError


# ── Rate Limiting (in-memory, per IP) ──────────────────

request_log: dict[str, list[float]] = defaultdict(list)

MAX_REQUESTS = 30      # requests per window
WINDOW_SECONDS = 60    # window size


async def rate_limit_middleware(request: Request, call_next):
    """Block requests if an IP exceeds MAX_REQUESTS in WINDOW_SECONDS."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Remove timestamps outside the window
    request_log[client_ip] = [
        t for t in request_log[client_ip] if now - t < WINDOW_SECONDS
    ]

    if len(request_log[client_ip]) >= MAX_REQUESTS:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")

    request_log[client_ip].append(now)
    return await call_next(request)


# ── App Setup ──────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run init_db on startup so tables are always ready."""
    init_db()
    yield


app = FastAPI(title="Payment Token Vault", lifespan=lifespan)

# Allow frontend to communicate with API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, this would be specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(rate_limit_middleware)

@app.get("/", include_in_schema=False)
def serve_frontend():
    """Serve the frontend UI."""
    return FileResponse("static/index.html")


# ── Request / Response Models ──────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "service"

class LoginRequest(BaseModel):
    username: str
    password: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str

class TokenizeRequest(BaseModel):
    card_number: str

class TokenizeResponse(BaseModel):
    token: str
    masked_pan: str

class DetokenizeRequest(BaseModel):
    token: str
    reason: str | None = None

class DetokenizeResponse(BaseModel):
    pan: str

class TokenMetadataResponse(BaseModel):
    token: str
    masked_pan: str
    created_at: str
    last_used_at: str | None
    expires_at: str | None
    is_revoked: bool

class MessageResponse(BaseModel):
    message: str


# ── Auth Endpoints (public) ───────────────────────────

@app.post("/register", response_model=MessageResponse)
def register_endpoint(req: RegisterRequest):
    """Register a new user."""
    try:
        return services.register(req.username, req.password, req.role)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/login", response_model=AuthResponse)
def login_endpoint(req: LoginRequest):
    """Login and receive a JWT token."""
    try:
        return services.login(req.username, req.password)
    except ValueError as e:
        raise HTTPException(401, str(e))


# ── Protected Endpoints ───────────────────────────────

@app.post("/tokenize", response_model=TokenizeResponse)
def tokenize_endpoint(
    req: TokenizeRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Tokenize a card number. Accepts optional X-Idempotency-Key header."""
    idempotency_key = request.headers.get("x-idempotency-key")
    try:
        return services.tokenize(
            req.card_number,
            role=current_user["role"],
            idempotency_key=idempotency_key,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/detokenize", response_model=DetokenizeResponse)
def detokenize_endpoint(
    req: DetokenizeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Detokenize — retrieve the original card number (admin only)."""
    try:
        return services.detokenize(
            req.token, role=current_user["role"], reason=req.reason
        )
    except PermissionError:
        raise HTTPException(403, "Admin role required")
    except ValueError as e:
        raise HTTPException(404, str(e))
    except TokenDecryptionError:
        raise HTTPException(500, "Internal error processing token")


@app.post("/token/{token_id}/revoke", response_model=MessageResponse)
def revoke_endpoint(
    token_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Revoke a token so it can no longer be detokenized (admin only)."""
    try:
        return services.revoke_token(token_id, role=current_user["role"])
    except PermissionError:
        raise HTTPException(403, "Admin role required")
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/token/{token_id}", response_model=TokenMetadataResponse)
def metadata_endpoint(
    token_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get non-sensitive metadata for a token."""
    try:
        return services.get_token_metadata(token_id, role=current_user["role"])
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/audit-log")
def audit_endpoint(current_user: dict = Depends(get_current_user)):
    """View all audit log entries (admin only)."""
    try:
        return services.get_audit_log(role=current_user["role"])
    except PermissionError:
        raise HTTPException(403, "Admin role required")