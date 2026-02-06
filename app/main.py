from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import hmac
import hashlib
import base64
import json
import time

app = FastAPI(title="FoxGuard API")

# ------------------------------------------------------------------
# Config / Secrets
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY")

if not SIGNING_KEY:
    raise RuntimeError("FOXGUARD_SIGNING_KEY is not set")


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class ActivateRequest(BaseModel):
    license_key: str
    device_id: str
    app_version: str


class ActivateResponse(BaseModel):
    plan: str
    expires_at: int
    license_token: str


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def sign_payload(payload: dict) -> str:
    """
    Create a signed license token.
    Token format (simple, JWT-like but custom):

    base64(payload_json).base64(signature)
    """
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode()

    signature = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    signature_b64 = base64.urlsafe_b64encode(signature).decode()

    return f"{payload_b64}.{signature_b64}"


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "service": "FoxGuard",
        "status": "online"
    }


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.post("/activate", response_model=ActivateResponse)
def activate(req: ActivateRequest):
    """
    V1 activation logic (stubbed):

    - Accept any non-empty license key
    - Issue a Pro license token
    - Valid for 30 days
    """

    if not req.license_key.strip():
        raise HTTPException(status_code=400, detail="Invalid license key")

    now = int(time.time())
    expires_at = now + (30 * 24 * 60 * 60)  # 30 days

    payload = {
        "license_key_last4": req.license_key[-4:],
        "device_id": req.device_id,
        "plan": "pro",
        "issued_at": now,
        "expires_at": expires_at,
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan="pro",
        expires_at=expires_at,
        license_token=token
    )
