from datetime import datetime
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app import services
from app.services import TokenDecryptionError

app = FastAPI(title="Payment Token Vault")


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
    created_at: datetime
    last_used_at: datetime | None


@app.post("/tokenize", response_model=TokenizeResponse)
def tokenize_endpoint(req: TokenizeRequest, x_role: str = Header(default="services")):
    try:
        return services.tokenize(req.card_number, role=x_role)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/detokenize", response_model=DetokenizeResponse)
def detokenize_endpoint(req: DetokenizeRequest, x_role: str = Header(default="services")):
    try:
        return services.detokenize(req.token, role=x_role, reason=req.reason)
    except PermissionError:
        raise HTTPException(403, "Admin role required")
    except ValueError as e:
        raise HTTPException(404, str(e))
    except TokenDecryptionError:
        raise HTTPException(500, "Internal error processing token")


@app.get("/token/{token_id}", response_model=TokenMetadataResponse)
def metadata_endpoint(token_id: str, x_role: str = Header(default="services")):
    try:
        return services.get_token_metadata(token_id, role=x_role)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/audit-log")
def audit_endpoint(x_role: str = Header(default="services")):
    try:
        return services.get_audit_log(role=x_role)
    except PermissionError:
        raise HTTPException(403, "Admin role required")