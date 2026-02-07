from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime, timezone
from collections import defaultdict

app = FastAPI(title="FoxGuard API")

# ------------------------------------------------------------------
# Config / Secrets
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY")

if not SIGNING_KEY:
    raise RuntimeError("FOXGUARD_SIGNING_KEY is not set")

# ------------------------------------------------------------------
# In-memory usage tracking (v1)
# key = (account_or_license, device_id, YYYY-MM-DD)
# ------------------------------------------------------------------

usage_counter = defaultdict(int)

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


class CheckRequest(BaseModel):
    license_token: str
    action: str | None = "batch_execute"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def sign_payload(payload: dict) -> str:
    """
    Create a signed license token.
    Format:
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


def verify_license_token(token: str) -> dict:
    """
    Verify token signature + expiration.
    Returns payload if valid.
    """
    try:
        payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed token")

    expected_sig = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    actual_sig = base64.urlsafe_b64decode(signature_b64.encode())

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    payload_json = base64.urlsafe_b64decode(payload_b64.encode())
    payload = json.loads(payload_json)

    now = int(time.time())
    if payload.get("expires_at") and payload["expires_at"] < now:
        raise HTTPException(status_code=401, detail="License expired")

    return payload


def utc_day_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def end_of_utc_day_ts() -> int:
    return int(
        datetime.now(timezone.utc)
        .replace(hour=23, minute=59, second=59)
        .timestamp()
    )


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
        "account_id": f"local-{req.license_key[-4:]}",  # placeholder until Base44
        "license_key_last4": req.license_key[-4:],
        "device_id": req.device_id,
        "plan": "pro",
        "limits": {
            "daily_batches": None  # unlimited
        },
        "policy": {
            "requires_online": False,
            "offline_allowed": True
        },
        "issued_at": now,
        "expires_at": expires_at,
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan="pro",
        expires_at=expires_at,
        license_token=token
    )


@app.post("/check")
def check(req: CheckRequest):
    """
    Runtime enforcement endpoint.
    Called before each batch execution.
    """

    payload = verify_license_token(req.license_token)

    account_id = payload.get("account_id", payload.get("license_key_last4"))
    device_id = payload.get("device_id")
    plan = payload.get("plan", "free")
    limits = payload.get("limits", {})
    policy = payload.get("policy", {})

    # ---- Online enforcement (future-safe)
    if policy.get("requires_online") is True:
        # Token validation already confirms online trust
        pass

    # ---- Pro users: always allowed
    if plan == "pro":
        return {
            "allowed": True,
            "remaining": None,
            "reset_at": None
        }

    # ---- Free tier enforcement
    daily_limit = limits.get("daily_batches", 5)

    today = utc_day_key()
    usage_key = (account_id, device_id, today)
    current_count = usage_counter[usage_key]

    if current_count >= daily_limit:
        return {
            "allowed": False,
            "reason": "daily_limit_exceeded",
            "limit": daily_limit,
            "reset_at": end_of_utc_day_ts()
        }

    # ---- Allow + increment
    usage_counter[usage_key] += 1

    return {
        "allowed": True,
        "remaining": daily_limit - usage_counter[usage_key],
        "reset_at": end_of_utc_day_ts()
    }
