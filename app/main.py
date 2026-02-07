from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import os
import hmac
import hashlib
import base64
import json
import time
from typing import Any, Dict, Optional, Tuple

import httpx

app = FastAPI(title="FoxGuard API", version="0.2.0")

# ------------------------------------------------------------------
# Config / Secrets (Render Environment Variables)
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY", "")
BASE44_ENTITLEMENTS_URL = os.getenv("BASE44_ENTITLEMENTS_URL", "")
FOXGUARD_BASE44_API_KEY = os.getenv("FOXGUARD_BASE44_API_KEY", "")
TOKEN_TTL_DAYS = int(os.getenv("FOXGUARD_TOKEN_TTL_DAYS", "30"))

# Safety timeouts for outbound calls
HTTP_TIMEOUT_SECONDS = float(os.getenv("FOXGUARD_HTTP_TIMEOUT", "8.0"))

if not SIGNING_KEY:
    raise RuntimeError("FOXGUARD_SIGNING_KEY is not set")


# ------------------------------------------------------------------
# In-memory usage counters (v1)
# NOTE: resets on deploy/restart; we’ll persist later.
# Keys: (account_id, yyyymmdd, action) -> count
# ------------------------------------------------------------------
USAGE: Dict[Tuple[str, str, str], int] = {}


def _today_yyyymmdd() -> str:
    return time.strftime("%Y%m%d", time.gmtime())


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
    limits: Dict[str, Any] = Field(default_factory=dict)


class CheckRequest(BaseModel):
    license_token: str
    device_id: str
    action: str = "batch"


class CheckResponse(BaseModel):
    ok: bool
    plan: str
    expires_at: int
    remaining_today: int
    requires_online: bool
    offline_allowed: bool


class ReportUsageRequest(BaseModel):
    license_token: str
    device_id: str
    action: str = "batch"
    amount: int = 1


class ReportUsageResponse(BaseModel):
    ok: bool
    used_today: int
    remaining_today: int
    daily_limit: int


# ------------------------------------------------------------------
# Token helpers (custom JWT-like)
# token = b64(payload_json) + "." + b64(hmac_sha256(payload_b64))
# ------------------------------------------------------------------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_decode(s: str) -> bytes:
    # restore padding
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_payload(payload: dict) -> str:
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    payload_b64 = _b64u_encode(payload_json)

    sig = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()

    sig_b64 = _b64u_encode(sig)
    return f"{payload_b64}.{sig_b64}"


def verify_token(token: str) -> dict:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed license token")

    expected_sig = hmac.new(
        SIGNING_KEY.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).digest()
    expected_sig_b64 = _b64u_encode(expected_sig)

    # constant-time compare
    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    try:
        payload = json.loads(_b64u_decode(payload_b64))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    now = int(time.time())
    exp = int(payload.get("expires_at", 0))
    if exp and now > exp:
        raise HTTPException(status_code=401, detail="Token expired")

    return payload


# ------------------------------------------------------------------
# Base44 fetch
# Your Base44 function checks: req.headers.get('x-api-key')
# So FoxGuard must send header: x-api-key: <FOXGUARD_BASE44_API_KEY>
# ------------------------------------------------------------------

async def fetch_entitlements_from_base44(account_id: str) -> dict:
    if not BASE44_ENTITLEMENTS_URL:
        raise HTTPException(status_code=500, detail="BASE44_ENTITLEMENTS_URL not set")
    if not FOXGUARD_BASE44_API_KEY:
        raise HTTPException(status_code=500, detail="FOXGUARD_BASE44_API_KEY not set")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": FOXGUARD_BASE44_API_KEY,
    }
    body = {"account_id": account_id}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.post(BASE44_ENTITLEMENTS_URL, headers=headers, json=body)
    except httpx.RequestError as e:
        # Render will otherwise show this as a 502 if uncaught
        raise HTTPException(status_code=502, detail=f"Base44 unreachable: {str(e)}")

    if r.status_code == 401:
        raise HTTPException(status_code=502, detail="Base44 rejected x-api-key (401)")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Base44 error {r.status_code}: {r.text[:300]}")

    try:
        return r.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Base44 returned non-JSON response")


def entitlement_daily_limit(ent: dict, action: str) -> int:
    # v1 only enforces daily_batches for action="batch"
    limits = ent.get("limits") or {}
    if action == "batch":
        return int(limits.get("daily_batches", 0) or 0)
    return 0


def usage_count(account_id: str, action: str) -> int:
    key = (account_id, _today_yyyymmdd(), action)
    return int(USAGE.get(key, 0))


def usage_add(account_id: str, action: str, amount: int) -> int:
    key = (account_id, _today_yyyymmdd(), action)
    USAGE[key] = int(USAGE.get(key, 0)) + int(amount)
    return int(USAGE[key])


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.get("/")
def root():
    return {"service": "FoxGuard", "status": "online"}


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/health")
def health():
    # Don’t leak secrets; just tell if configured.
    return {
        "ok": True,
        "has_signing_key": bool(SIGNING_KEY),
        "has_base44_entitlements_url": bool(BASE44_ENTITLEMENTS_URL),
        "has_base44_api_key": bool(FOXGUARD_BASE44_API_KEY),
        "token_ttl_days": TOKEN_TTL_DAYS,
    }


@app.post("/activate", response_model=ActivateResponse)
async def activate(req: ActivateRequest):
    """
    Activation (Base44-driven):
    - Fetch entitlement snapshot from Base44
    - Bind to device_id
    - Mint signed token
    """

    if not req.account_id.strip():
        raise HTTPException(status_code=400, detail="account_id required")
    if not req.device_id.strip():
        raise HTTPException(status_code=400, detail="device_id required")

    ent = await fetch_entitlements_from_base44(req.account_id)

    now = int(time.time())

    # Base44 returns expires_at for paid plans (or null). We cap by FOXGUARD_TOKEN_TTL_DAYS.
    ttl_cap = now + (TOKEN_TTL_DAYS * 24 * 60 * 60)
    base44_exp = ent.get("expires_at")
    try:
        base44_exp_int = int(base44_exp) if base44_exp else 0
    except Exception:
        base44_exp_int = 0

    expires_at = min(ttl_cap, base44_exp_int) if base44_exp_int else ttl_cap

    plan = str(ent.get("plan") or "free")
    policy = ent.get("policy") or {}
    requires_online = bool(policy.get("requires_online", True))
    offline_allowed = bool(policy.get("offline_allowed", False))

    payload = {
        "schema": "fg_v1",
        "issued_at": now,
        "expires_at": expires_at,

        "account_id": req.account_id,
        "device_id": req.device_id,
        "app_version": req.app_version,

        # Entitlements snapshot (what Base44 says is true *right now*)
        "plan": plan,
        "status": ent.get("status", "active"),
        "license_status": ent.get("license_status", "active"),
        "trial_ends_at": ent.get("trial_ends_at"),
        "addons": ent.get("addons", {}),
        "limits": ent.get("limits", {}),
        "policy": {
            "requires_online": requires_online,
            "offline_allowed": offline_allowed,
        },
        "fraud_flag": bool(ent.get("fraud_flag", False)),
    }

    token = sign_payload(payload)

    return ActivateResponse(
        plan=plan,
        expires_at=expires_at,
        license_token=token,
        limits=payload.get("limits", {}),
    )


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    """
    Runtime gate:
    - validate signature + expiration
    - enforce device binding
    - enforce daily quota (in-memory for now)
    """
    payload = verify_token(req.license_token)

    token_device = payload.get("device_id", "")
    if token_device and req.device_id != token_device:
        raise HTTPException(status_code=401, detail="Device mismatch")

    if payload.get("fraud_flag"):
        raise HTTPException(status_code=403, detail="Account flagged")

    account_id = str(payload.get("account_id") or "")
    if not account_id:
        raise HTTPException(status_code=401, detail="Token missing account_id")

    policy = payload.get("policy") or {}
    requires_online = bool(policy.get("requires_online", True))
    offline_allowed = bool(policy.get("offline_allowed", False))

    daily_limit = entitlement_daily_limit(payload, req.action)
    used = usage_count(account_id, req.action)
    remaining = max(daily_limit - used, 0) if daily_limit > 0 else 0

    # If there's a limit and they are out, block
    if daily_limit > 0 and used >= daily_limit:
        raise HTTPException(status_code=402, detail="Daily quota exceeded")

    return CheckResponse(
        ok=True,
        plan=str(payload.get("plan") or "free"),
        expires_at=int(payload.get("expires_at") or 0),
        remaining_today=remaining,
        requires_online=requires_online,
        offline_allowed=offline_allowed,
    )


@app.post("/report_usage", response_model=ReportUsageResponse)
def report_usage(req: ReportUsageRequest):
    """
    Usage consumption:
    Call this AFTER a batch run completes successfully (or at start, your call).
    """
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="amount must be >= 1")

    payload = verify_token(req.license_token)

    token_device = payload.get("device_id", "")
    if token_device and req.device_id != token_device:
        raise HTTPException(status_code=401, detail="Device mismatch")

    if payload.get("fraud_flag"):
        raise HTTPException(status_code=403, detail="Account flagged")

    account_id = str(payload.get("account_id") or "")
    if not account_id:
        raise HTTPException(status_code=401, detail="Token missing account_id")

    daily_limit = entitlement_daily_limit(payload, req.action)
    if daily_limit <= 0:
        # If no limit defined, treat as unlimited (Pro later)
        return ReportUsageResponse(ok=True, used_today=0, remaining_today=0, daily_limit=0)

    used_after = usage_add(account_id, req.action, req.amount)

    if used_after > daily_limit:
        # roll back the increment for sanity
        usage_add(account_id, req.action, -req.amount)
        raise HTTPException(status_code=402, detail="Daily quota exceeded")

    remaining = max(daily_limit - used_after, 0)

    return ReportUsageResponse(
        ok=True,
        used_today=used_after,
        remaining_today=remaining,
        daily_limit=daily_limit,
    )
