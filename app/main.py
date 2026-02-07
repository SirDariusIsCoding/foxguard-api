from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import hmac
import hashlib
import base64
import json
import time
import requests
from typing import Dict, Tuple

app = FastAPI(title="FoxGuard API")

# ------------------------------------------------------------------
# Config / Secrets
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY")
BASE44_ENTITLEMENTS_URL = os.getenv("BASE44_ENTITLEMENTS_URL")
BASE44_API_KEY = os.getenv("FOXGUARD_BASE44_API_KEY")
TOKEN_TTL_DAYS = int(os.getenv("FOXGUARD_TOKEN_TTL_DAYS", "30"))

if not SIGNING_KEY:
    raise RuntimeError("FOXGUARD_SIGNING_KEY is not set")

if not BASE44_ENTITLEMENTS_URL or not BASE44_API_KEY:
    raise RuntimeError("Base44 configuration missing")

# ------------------------------------------------------------------
# In-memory usage store (v1)
# key = (account_id, device_id, YYYY-MM-DD)
# ------------------------------------------------------------------

USAGE: Dict[Tuple[str, str, str], int] = {}

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class ActivateRequest(BaseModel):
    account_id: str
    device_id: str
    app_version: str


class ActivateResponse(BaseModel):
    plan: str
    expires_at: int
    license_token: str


class CheckRequest(BaseModel):
    license_token: str
    action: str


class CheckResponse(BaseModel):
    allowed: bool
    remaining: int | None = None
    reset_at: int | None = None
    reason: str | None = None


class ReportUsageRequest(BaseModel):
    license_token: str
    action: str


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def sign_payload(payload: dict) -> str:
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode()

    signature = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    signature_b64 = base64.urlsafe_b64encode(signature).decode()
    return f"{payload_b64}.{signature_b64}"


def verify_token(token: str) -> dict:
    try:
        payload_b64, sig_b64 = token.split(".")
        expected_sig = hmac.new(
            SIGNING_KEY.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(
            base64.urlsafe_b64encode(expected_sig).decode(),
            sig_b64
        ):
            raise ValueError("Invalid signature")

        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
        if payload["expires_at"] < int(time.time()):
            raise ValueError("Token expired")

        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid license token")


def fetch_entitlements(account_id: str) -> dict:
    resp = requests.post(
        BASE44_ENTITLEMENTS_URL,
        headers={
            "Content-Type": "application/json",
            "x-api-key": BASE44_API_KEY,
        },
        json={"account_id": account_id},
        timeout=5,
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch entitlements")

    return resp.json()


def today_key() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.get("/")
def root():
    return {"service": "FoxGuard", "status": "online"}


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.post("/activate", response_model=ActivateResponse)
def activate(req: ActivateRequest):
    """
    Activation:
    - Fetch entitlements from Base44
    - Sign snapshot into token
    """

    entitlements = fetch_entitlements(req.account_id)

    now = int(time.time())
    expires_at = entitlements.get("expires_at") or (
        now + TOKEN_TTL_DAYS * 86400
    )

    payload = {
        "account_id": entitlements["account_id"],
        "device_id": req.device_id,
        "plan": entitlements["plan"],
        "limits": entitlements["limits"],
        "policy": entitlements["policy"],
        "issued_at": now,
        "expires_at": expires_at,
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan=payload["plan"],
        expires_at=expires_at,
        license_token=token,
    )


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    """
    Runtime enforcement before a batch runs
    """

    payload = verify_token(req.license_token)

    account_id = payload["account_id"]
    device_id = payload["device_id"]
    limits = payload.get("limits", {})
    policy = payload.get("policy", {})

    if policy.get("requires_online"):
        pass  # already online by virtue of calling this endpoint

    daily_limit = limits.get("daily_batches", 0)
    key = (account_id, device_id, today_key())
    used = USAGE.get(key, 0)

    if daily_limit and used >= daily_limit:
        reset_at = int(
            time.mktime(
                time.strptime(today_key(), "%Y-%m-%d")
            )
        ) + 86400

        return CheckResponse(
            allowed=False,
            reason="daily_limit_exceeded",
            reset_at=reset_at,
        )

    return CheckResponse(
        allowed=True,
        remaining=(daily_limit - used) if daily_limit else None,
        reset_at=None,
    )


@app.post("/report_usage")
def report_usage(req: ReportUsageRequest):
    """
    Async usage reporting AFTER a batch completes
    """

    payload = verify_token(req.license_token)

    account_id = payload["account_id"]
    device_id = payload["device_id"]

    key = (account_id, device_id, today_key())
    USAGE[key] = USAGE.get(key, 0) + 1

    return {"status": "recorded", "used": USAGE[key]}
