"""
RBAC 权限控制依赖注入
基于角色的访问控制，用于 FastAPI Depends 注入
"""
from typing import List

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.apps.auth.models import User, Role, Permission
from app.core.database import get_db
from app.apps.auth.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """从 JWT Token 解析当前用户"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="用户已被禁用",
        )
    return user


def require_permissions(allowed_permissions: List[str]):
    """Permission checker dependency factory.
    Checks whether the current user possesses any of the roles or permissions listed in ``allowed_permissions``.
    Supports admin bypass and backward compatibility for role-based checks.
    """
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role_names = {role.name for role in current_user.roles}
        user_permission_names = {perm.name for role in current_user.roles for perm in role.permissions}
        
        # Admin bypass
        if "ADMIN" in user_role_names or "admin:*" in user_permission_names:
            return current_user
            
        # Check roles or permissions (OR logic)
        has_role = any(r in user_role_names for r in allowed_permissions)
        has_perm = any(p in user_permission_names for p in allowed_permissions)
        
        if not (has_role or has_perm):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"权限不足，需要以下之一: {', '.join(allowed_permissions)}",
            )
        return current_user
    return permission_checker

# Backward compatibility: keep the old name for existing imports
require_roles = require_permissions
