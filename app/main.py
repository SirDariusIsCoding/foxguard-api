from fastapi import FastAPI, HTTPException, Header
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
# Environment
# ------------------------------------------------------------------

SIGNING_KEY = os.getenv("FOXGUARD_SIGNING_KEY")
BASE44_API_KEY = os.getenv("FOXGUARD_BASE44_API_KEY")
BASE44_ENTITLEMENTS_URL = os.getenv("BASE44_ENTITLEMENTS_URL")
TOKEN_TTL_DAYS = int(os.getenv("FOXGUARD_TOKEN_TTL_DAYS", "30"))

if not all([SIGNING_KEY, BASE44_API_KEY, BASE44_ENTITLEMENTS_URL]):
    raise RuntimeError("Missing required FoxGuard environment variables")

# ------------------------------------------------------------------
# Models (MATCH BASE44 EXPECTATIONS)
# ------------------------------------------------------------------

class ActivateRequest(BaseModel):
    account_id: str
    device_id: str
    app_version: str


class ActivateResponse(BaseModel):
    plan: str
    expires_at: int
    license_token: str
    limits: dict


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


async def fetch_entitlements_from_base44(account_id: str) -> dict:
    """
    Calls Base44 getEntitlements.ts
    EXPECTS:
      - POST
      - JSON body with account_id
      - Header: x-api-key
    """
headers = {
    "Content-Type": "application/json",
    "api_key": BASE44_API_KEY
}


    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            BASE44_ENTITLEMENTS_URL,
            headers=headers,
            json={"account_id": account_id},
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Base44 error: {resp.status_code}"
        )

    return resp.json()


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
    Canonical activation flow:
    1. Validate request
    2. Fetch entitlements from Base44
    3. Normalize response
    4. Issue signed FoxGuard token
    """

    try:
        if not req.account_id or not req.device_id:
            raise HTTPException(status_code=400, detail="Missing account_id or device_id")

        ent = await fetch_entitlements_from_base44(req.account_id)

        # -------------------------------
        # Normalize Base44 response
        # -------------------------------

        plan = ent.get("plan", "free")
        license_status = ent.get("license_status", "inactive")
        expires_at = ent.get("expires_at")
        limits = ent.get("limits") or {}
        policy = ent.get("policy") or {}

        now = int(time.time())
        max_exp = now + (TOKEN_TTL_DAYS * 24 * 60 * 60)

        try:
            expires_at = int(expires_at) if expires_at else max_exp
        except Exception:
            expires_at = max_exp

        expires_at = min(expires_at, max_exp)

        # -------------------------------
        # Build FoxGuard license payload
        # -------------------------------

        payload = {
            "schema": "foxguard_v1",
            "issued_at": now,
            "expires_at": expires_at,
            "account_id": req.account_id,
            "device_id": req.device_id,
            "app_version": req.app_version,
            "plan": plan,
            "license_status": license_status,
            "limits": limits,
            "policy": {
                "requires_online": bool(policy.get("requires_online", True)),
                "offline_allowed": bool(policy.get("offline_allowed", False)),
            },
            "fraud_flag": bool(ent.get("fraud_flag", False)),
        }

        token = sign_payload(payload)

        return ActivateResponse(
            plan=plan,
            expires_at=expires_at,
            license_token=token,
            limits=limits,
        )

    except HTTPException:
        raise
    except Exception as e:
        # Critical: prevents "returned JSON + 502"
        raise HTTPException(
            status_code=500,
            detail=f"Activation failed: {str(e)}"
        )
