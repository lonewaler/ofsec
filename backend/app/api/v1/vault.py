"""
OfSec V3 — Vault API Router
===========================
Secure vault endpoints for API keys management.
"""

from typing import Optional

from fastapi import APIRouter, status
from pydantic import BaseModel
from sqlalchemy.future import select

from app.api.deps import DbSession
from app.core.encryption import encrypt_secret
from app.models.vault import SecretVault

router = APIRouter(tags=["Vault"])

# In-memory storage for the decrypted master password, 
# strictly temporary for background AI tasks to unlock secrets.
ACTIVE_MASTER_PASSWORD: Optional[str] = None


class StoreKeyRequest(BaseModel):
    service_name: str
    api_key: str
    master_password: str


class UnlockVaultRequest(BaseModel):
    master_password: str


@router.post("/key", status_code=status.HTTP_200_OK)
async def store_secret_key(
    req: StoreKeyRequest,
    db: DbSession,
):
    """Encrypt and store an API key for a specific service."""
    encrypted_key = encrypt_secret(req.api_key, req.master_password)

    query = select(SecretVault).where(SecretVault.service_name == req.service_name)
    result = await db.execute(query)
    existing_secret = result.scalar_one_or_none()

    if existing_secret:
        existing_secret.encrypted_key = encrypted_key
    else:
        new_secret = SecretVault(
            service_name=req.service_name,
            encrypted_key=encrypted_key
        )
        db.add(new_secret)

    await db.commit()
    return {"status": "success", "message": f"Secret key for '{req.service_name}' stored securely."}


@router.post("/unlock", status_code=status.HTTP_200_OK)
async def unlock_vault(req: UnlockVaultRequest):
    """Temporarily stores the master password in memory for background tasks to use."""
    global ACTIVE_MASTER_PASSWORD
    ACTIVE_MASTER_PASSWORD = req.master_password
    return {"status": "success", "message": "Vault unlocked for background workers."}
