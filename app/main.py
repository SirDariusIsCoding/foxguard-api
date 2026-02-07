from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import hmac
import hashlib
import base64
import json
import time
from datetime import datetime, timezone
from collections import defaultdict

import httpx

app = FastAPI(title="FoxGuard API")

# ------------------------------------------------------------------
# Config / Secrets
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY")
if not SIGNING_KEY:
    raise RuntimeError("FOXGUARD_SIGNING_KEY is not set")

BASE44_ENTITLEMENTS_URL = os.getenv("BASE44_ENTITLEMENTS_URL")  # Base44 function URL: getEntitlements
FOXGUARD_BASE44_API_KEY = os.getenv("FOXGUARD_BASE44_API_KEY")  # must match Base44 env
BASE44_ME_URL = os.getenv("BASE44_ME_URL")  # Base44 /auth/me (or equivalent)

TOKEN_TTL_DAYS = int(os.getenv("FOXGUARD_TOKEN_TTL_DAYS", "30"))

# ------------------------------------------------------------------
# In-memory usage tracking (v1)
# NOTE: This resets on redeploy. Later: Redis/Postgres.
# key = (account_id, device_id, YYYY-MM-DD, action)
# ------------------------------------------------------------------

usage_counter = defaultdict(int)

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class ActivateRequest(BaseModel):
    # Legacy path (no login yet):
    license_key: Optional[str] = None

    # Login bridge path:
    account_id: Optional[str] = None
    session_token: Optional[str] = None  # from Base44 login/session

    device_id: str
    app_version: str


class ActivateResponse(BaseModel):
    plan: str
    expires_at: int
    license_token: str
    entitlement: Optional[Dict[str, Any]] = None  # helpful for debugging/UI


class CheckRequest(BaseModel):
    license_token: str
    action: str = "batch_execute"
    units: int = 1  # future use; v1 mostly 1 per batch


class ReportUsageRequest(BaseModel):
    license_token: str
    action: str = "batch_execute"
    units: int = 1
    batch_id: Optional[str] = None  # optional idempotency later


# ------------------------------------------------------------------
# Helpers: signing + verification
# ------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


def sign_payload(payload: dict) -> str:
    """
    Token format:
    base64(payload_json).base64(signature)
    """
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    payload_b64 = _b64e(payload_json)

    signature = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    signature_b64 = _b64e(signature)
    return f"{payload_b64}.{signature_b64}"


def verify_license_token(token: str) -> dict:
    try:
        payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed token")

    expected_sig = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    try:
        actual_sig = _b64d(signature_b64)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed token signature")

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    try:
        payload_json = _b64d(payload_b64)
        payload = json.loads(payload_json)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed token payload")

    now = int(time.time())
    exp = payload.get("expires_at")
    if exp is not None and int(exp) < now:
        raise HTTPException(status_code=401, detail="License token expired")

    return payload


# ------------------------------------------------------------------
# Helpers: usage window + counters
# ------------------------------------------------------------------

def utc_day_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def end_of_utc_day_ts() -> int:
    return int(
        datetime.now(timezone.utc)
        .replace(hour=23, minute=59, second=59)
        .timestamp()
    )


def _usage_key(account_id: str, device_id: str, day: str, action: str) -> tuple:
    return (account_id, device_id, day, action)


# ------------------------------------------------------------------
# Helpers: Base44 integration
# ------------------------------------------------------------------

async def base44_validate_session(account_id: str, session_token: str) -> None:
    """
    Validates that session_token is valid and belongs to account_id.
    This assumes Base44 /auth/me responds with the current account info.
    """
    if not BASE44_ME_URL:
        raise HTTPException(status_code=500, detail="BASE44_ME_URL not configured")

    headers = {
        "Authorization": f"Bearer {session_token}",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(BASE44_ME_URL, headers=headers)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid session_token")

        data = r.json()
        # We expect it to contain account_id (adjust this if Base44 returns a different shape)
        returned_id = data.get("account_id") or data.get("id") or data.get("user", {}).get("account_id")
        if returned_id and str(returned_id) != str(account_id):
            raise HTTPException(status_code=401, detail="Session does not match account_id")


async def base44_get_entitlements(account_id: str) -> Dict[str, Any]:
    """
    Calls your Base44 getEntitlements function.
    Your Base44 function expects:
      - header x-api-key
      - JSON body { account_id }
    """
    if not BASE44_ENTITLEMENTS_URL or not FOXGUARD_BASE44_API_KEY:
        raise HTTPException(status_code=500, detail="Base44 entitlements integration not configured")

    headers = {
        "x-api-key": FOXGUARD_BASE44_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(BASE44_ENTITLEMENTS_URL, headers=headers, json={"account_id": account_id})
        if r.status_code == 401:
            raise HTTPException(status_code=500, detail="Base44 entitlements unauthorized (check API key)")
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Account not found in Base44")
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Base44 entitlements error: {r.status_code}")

        return r.json()


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
    """
    Activation + token issuance.

    Supports two paths:
    1) Login bridge path (preferred):
       - account_id + session_token provided
       - FoxGuard validates session with Base44
       - FoxGuard fetches Base44 entitlements
       - FoxGuard signs token embedding the entitlement snapshot

    2) Legacy license_key path (temporary):
       - license_key provided
       - issues a stub "pro" token (useful during bring-up)
    """
    now = int(time.time())

    # ----------------------------
    # Path A: account login bridge
    # ----------------------------
    if req.account_id and req.session_token:
        # Validate session is real (prevents random account_id spoofing)
        await base44_validate_session(req.account_id, req.session_token)

        ent = await base44_get_entitlements(req.account_id)

        plan = ent.get("plan", "free")
        fraud_flag = bool(ent.get("fraud_flag", False))
        limits = ent.get("limits", {}) or {}
        policy = ent.get("policy", {}) or {}

        # Token expiry: short-lived “license token” that must refresh periodically.
        # If Base44 has expires_at, we never go past it.
        entitlement_expires_at = ent.get("expires_at")  # may be null
        token_ttl_seconds = TOKEN_TTL_DAYS * 24 * 60 * 60
        token_exp = now + token_ttl_seconds

        if entitlement_expires_at:
            try:
                token_exp = min(token_exp, int(entitlement_expires_at))
            except Exception:
                pass

        payload = {
            "schema_version": "v1",
            "account_id": req.account_id,
            "device_id": req.device_id,
            "app_version": req.app_version,
            "plan": plan,
            "limits": limits,
            "policy": policy,
            "fraud_flag": fraud_flag,
            "issued_at": now,
            "expires_at": int(token_exp),
            "entitlement_snapshot": ent,  # embed full snapshot for offline verification
        }

        token = sign_payload(payload)

        return ActivateResponse(
            plan=plan,
            expires_at=int(token_exp),
            license_token=token,
            entitlement=ent
        )

    # ----------------------------
    # Path B: legacy license_key
    # ----------------------------
    if not req.license_key or not req.license_key.strip():
        raise HTTPException(status_code=400, detail="Provide account_id+session_token OR license_key")

    expires_at = now + (TOKEN_TTL_DAYS * 24 * 60 * 60)

    payload = {
        "schema_version": "v1",
        "account_id": f"legacy-{req.license_key[-4:]}",
        "license_key_last4": req.license_key[-4:],
        "device_id": req.device_id,
        "app_version": req.app_version,
        "plan": "pro",
        "limits": {"daily_batches": None},
        "policy": {"requires_online": False, "offline_allowed": True},
        "fraud_flag": False,
        "issued_at": now,
        "expires_at": expires_at,
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan="pro",
        expires_at=expires_at,
        license_token=token,
        entitlement=None
    )


@app.post("/check")
def check(req: CheckRequest):
    """
    Non-consuming gate check.
    Use this BEFORE a batch runs to decide allow/deny.

    Consumption happens in /report_usage after completion (async-friendly).
    """
    payload = verify_license_token(req.license_token)

    plan = payload.get("plan", "free")
    fraud_flag = bool(payload.get("fraud_flag", False))
    limits = payload.get("limits", {}) or {}
    policy = payload.get("policy", {}) or {}

    if fraud_flag:
        return {"allowed": False, "reason": "account_flagged"}

    # If Free requires online, they should be calling FoxGuard anyway (this endpoint is online).
    # Pro may be offline (no call).
    if plan == "pro":
        return {"allowed": True, "remaining": None, "reset_at": None}

    account_id = payload.get("account_id")
    device_id = payload.get("device_id")
    if not account_id or not device_id:
        raise HTTPException(status_code=401, detail="Token missing identity fields")

    daily_limit = limits.get("daily_batches", 5)
    day = utc_day_key()
    key = _usage_key(account_id, device_id, day, req.action)
    used = usage_counter[key]

    if used >= daily_limit:
        return {
            "allowed": False,
            "reason": "daily_limit_exceeded",
            "limit": daily_limit,
            "reset_at": end_of_utc_day_ts()
        }

    remaining = max(0, daily_limit - used)
    return {
        "allowed": True,
        "remaining": remaining,
        "reset_at": end_of_utc_day_ts()
    }


@app.post("/report_usage")
def report_usage(req: ReportUsageRequest):
    """
    Consumes usage AFTER a batch completes.
    This supports async enforcement (your batch can run, then report).

    For Free tier, this is what increments daily usage.
    """
    payload = verify_license_token(req.license_token)

    plan = payload.get("plan", "free")
    fraud_flag = bool(payload.get("fraud_flag", False))
    limits = payload.get("limits", {}) or {}

    if fraud_flag:
        return {"accepted": False, "reason": "account_flagged"}

    # Pro: no quota consumption needed (still accepted)
    if plan == "pro":
        return {"accepted": True, "plan": "pro", "remaining": None, "reset_at": None}

    account_id = payload.get("account_id")
    device_id = payload.get("device_id")
    if not account_id or not device_id:
        raise HTTPException(status_code=401, detail="Token missing identity fields")

    daily_limit = limits.get("daily_batches", 5)
    units = max(1, int(req.units))

    day = utc_day_key()
    key = _usage_key(account_id, device_id, day, req.action)

    usage_counter[key] += units
    used = usage_counter[key]

    if used > daily_limit:
        # We still accept the report, but signal they are now over quota.
        return {
            "accepted": True,
            "plan": "free",
            "over_quota": True,
            "limit": daily_limit,
            "used": used,
            "remaining": 0,
            "reset_at": end_of_utc_day_ts()
        }

    return {
        "accepted": True,
        "plan": "free",
        "over_quota": False,
        "limit": daily_limit,
        "used": used,
        "remaining": max(0, daily_limit - used),
        "reset_at": end_of_utc_day_ts()
    }
