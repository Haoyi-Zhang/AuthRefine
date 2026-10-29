"""Casbin RBAC enforcement with multi-tenant support and JWT integration."""

import logging
import os
from pathlib import Path
from typing import List, Tuple

import casbin
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger(__name__)

# ─── Configuration ──────────────────────────────────────────────────────────

# Allow anonymous access in dev/test; disable in production
ALLOW_ANONYMOUS = os.getenv("ALLOW_ANONYMOUS", "true").lower() == "true"

# JWT secret: required in production
_JWT_SECRET = os.getenv("JWT_SECRET")

if not ALLOW_ANONYMOUS and not _JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET must be set when ALLOW_ANONYMOUS=false. "
        "Generate a secure random secret (at least 32 chars)."
    )

# ─── Casbin Enforcer (lazy, absolute paths) ─────────────────────────────────

_SECURITY_DIR = Path(__file__).parent
_enforcer_instance: casbin.Enforcer | None = None


def _get_enforcer() -> casbin.Enforcer:
    """Get the Casbin enforcer (lazy singleton)."""
    global _enforcer_instance
    if _enforcer_instance is None:
        _enforcer_instance = casbin.Enforcer(
            str(_SECURITY_DIR / "rbac_model.conf"),
            str(_SECURITY_DIR / "rbac_policy.csv"),
        )
    return _enforcer_instance


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)


# ─── JWT Authentication ─────────────────────────────────────────────────────

async def get_current_tenant_and_roles(
    token: str = Depends(oauth2_scheme),
) -> Tuple[str, List[str]]:
    """Decode JWT and extract tenant_id and roles."""
    if not token:
        if ALLOW_ANONYMOUS:
            return "tenant1", ["ux_analyst"]
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide a valid Bearer token.",
        )

    try:
        from jose import JWTError, jwt

        secret = _JWT_SECRET or os.getenv("JWT_SECRET")
        if not secret:
            raise HTTPException(
                status_code=500,
                detail="JWT_SECRET not configured on server.",
            )
        algorithm = os.getenv("JWT_ALGORITHM", "HS256")

        payload = jwt.decode(token, secret, algorithms=[algorithm])
        tenant = payload.get("tenant_id", "tenant1")
        roles = payload.get("roles", ["ux_analyst"])

        if isinstance(roles, str):
            roles = [roles]

        return tenant, roles

    except HTTPException:
        raise
    except JWTError as e:
        logger.warning(f"Invalid JWT token: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except Exception as e:
        logger.exception(f"Token validation failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


# ─── RBAC Dependencies ──────────────────────────────────────────────────────

def require_permission(obj: str, act: str):
    """FastAPI dependency for RBAC permission checking."""

    async def dep(tenant_roles: Tuple[str, List[str]] = Depends(get_current_tenant_and_roles)):
        tenant, roles = tenant_roles
        enc = _get_enforcer()

        for role in roles:
            if enc.enforce(role, obj, act, tenant):
                return tenant

        logger.warning(f"Permission denied: roles={roles}, obj={obj}, act={act}, tenant={tenant}")
        raise HTTPException(status_code=403, detail="RBAC permission denied")

    return dep


# ─── Policy Management ──────────────────────────────────────────────────────

def add_policy(role: str, obj: str, act: str, tenant: str) -> bool:
    """Add a new RBAC policy rule."""
    return _get_enforcer().add_policy(role, obj, act, tenant)


def add_role_for_user(user: str, role: str, tenant: str) -> bool:
    """Assign a role to a user in a specific tenant."""
    return _get_enforcer().add_grouping_policy(user, role, tenant)


def remove_role_for_user(user: str, role: str, tenant: str) -> bool:
    """Remove a role from a user in a specific tenant."""
    return _get_enforcer().remove_grouping_policy(user, role, tenant)


def get_user_roles(user: str, tenant: str) -> List[str]:
    """Get all roles for a user in a specific tenant."""
    return _get_enforcer().get_roles_for_user_in_domain(user, tenant)


def get_permissions_for_role(role: str, tenant: str) -> List[dict]:
    """Get all permissions for a role in a specific tenant."""
    policies = _get_enforcer().get_filtered_policy(0, role, "", "", tenant)
    return [
        {"object": p[1], "action": p[2], "tenant": p[3]}
        for p in policies
        if len(p) >= 4
    ]
