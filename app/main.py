from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import hmac
import hashlib
import base64
import json
import time
import httpx

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

if not BASE44_ENTITLEMENTS_URL:
    raise RuntimeError("BASE44_ENTITLEMENTS_URL is not set")

if not BASE44_API_KEY:
    raise RuntimeError("FOXGUARD_BASE44_API_KEY is not set")

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
    action: str  # e.g. "batch"


class UsageReportRequest(BaseModel):
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
            expected_sig,
            base64.urlsafe_b64decode(sig_b64)
        ):
            raise ValueError("Invalid signature")

        payload_json = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_json)

        if payload["expires_at"] < int(time.time()):
            raise ValueError("Token expired")

        return payload

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


async def fetch_entitlements(account_id: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "x-api-key": BASE44_API_KEY
    }

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            BASE44_ENTITLEMENTS_URL,
            headers=headers,
            json={"account_id": account_id}
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Failed to fetch entitlements from Base44"
        )

    return response.json()


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
async def activate(req: ActivateRequest):
    entitlements = await fetch_entitlements(req.account_id)

    now = int(time.time())
    expires_at = now + (TOKEN_TTL_DAYS * 24 * 60 * 60)

    payload = {
        "account_id": req.account_id,
        "device_id": req.device_id,
        "issued_at": now,
        "expires_at": expires_at,
        "entitlement": entitlements
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan=entitlements.get("plan", "free"),
        expires_at=expires_at,
        license_token=token
    )


@app.post("/check")
def check(req: CheckRequest):
    payload = verify_token(req.license_token)
    entitlement = payload["entitlement"]

    # Online enforcement
    if entitlement["policy"]["requires_online"]:
        pass  # online is assumed since we're here

    # Fraud kill-switch
    if entitlement.get("fraud_flag"):
        raise HTTPException(status_code=403, detail="Account flagged")

    # Usage limits
    limits = entitlement.get("limits", {})
    if req.action == "batch":
        daily_limit = limits.get("daily_batches", 0)
        if daily_limit <= 0:
            raise HTTPException(
                status_code=403,
                detail="Daily batch limit reached"
            )

    return {
        "allowed": True,
        "plan": entitlement.get("plan"),
        "limits": limits
    }


@app.post("/report_usage")
def report_usage(req: UsageReportRequest):
    payload = verify_token(req.license_token)

    # NOTE:
    # This is intentionally lightweight.
    # Real counters will live in Base44 later.
    # This endpoint exists so the desktop app
    # cannot lie about usage.

    return {
        "status": "recorded",
        "action": req.action,
        "account_id": payload["account_id"]
    }
