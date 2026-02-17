"""
Saucemon admin routes.

Isolated SaaS admin endpoints that are enabled only when SAUCEMON_MODE=true.
"""

import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text

from auth.api_key_auth import get_current_user_or_api_key as get_current_user, require_scope
from auth.shared import db
from config.settings import AppConfig

router = APIRouter(
    prefix="/api/saucemon/admin",
    tags=["saucemon-admin"],
    dependencies=[Depends(require_scope("admin"))],
)


@router.get("/overview")
async def get_saucemon_admin_overview(current_user: dict = Depends(get_current_user)):
    """
    Return tenant and user summary for the Saucemon admin UI.

    This endpoint is intentionally scoped to a single physical-silo tenant
    represented by this container and /app/data/dockmon.db database.
    """
    if not AppConfig.SAUCEMON_MODE:
        raise HTTPException(status_code=404, detail="Saucemon admin mode is disabled")

    with db.get_session() as session:
        total_users = session.execute(text("SELECT COUNT(*) FROM users")).scalar() or 0
        role_rows = session.execute(
            text("SELECT role, COUNT(*) AS count FROM users GROUP BY role")
        ).fetchall()

    role_counts = {str(row.role): int(row.count) for row in role_rows}

    return {
        "mode": "enabled",
        "tenant": {
            "tenant_id": os.getenv("SAUCEMON_TENANT_ID", "default"),
            "database_path": "/app/data/dockmon.db",
            "deployment_model": "physical-silo",
        },
        "users": {
            "total": int(total_users),
            "admin": role_counts.get("admin", 0),
            "user": role_counts.get("user", 0),
            "readonly": role_counts.get("readonly", 0),
        },
        "requested_by": {
            "user_id": current_user.get("user_id"),
            "username": current_user.get("username"),
        },
    }
