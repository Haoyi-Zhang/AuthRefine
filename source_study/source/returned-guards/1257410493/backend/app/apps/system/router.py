from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
import asyncio
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.constants import WorkOrderStatus, SalesOrderStatus
from app.core.redis import CacheService, CACHE_KEYS
from app.apps.auth.dependencies import get_current_user, require_permissions as require_roles
from app.apps.auth.models import User
from app.apps.erp.models import Product, SalesOrder, Supplier
from app.apps.mes.models import WorkOrder
from app.apps.wms.models import Material
from app.apps.system.models import AuditLog
from app.apps.system.schemas import AuditLogResponse, DashboardStats

router = APIRouter()


# ===========================================
# 仪表盘统计
# ===========================================
@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """获取仪表盘统计数据（带缓存）"""
    # 尝试从缓存获取
    cached = CacheService.get(CACHE_KEYS['dashboard_stats'])
    if cached:
        return DashboardStats(**cached)

    total_products = db.query(func.count(Product.id)).scalar() or 0
    total_materials = db.query(func.count(Material.id)).scalar() or 0
    total_work_orders = db.query(func.count(WorkOrder.id)).scalar() or 0
    pending_work_orders = db.query(func.count(WorkOrder.id)).filter(
        WorkOrder.status.in_([WorkOrderStatus.PLANNED, WorkOrderStatus.NOT_STARTED])
    ).scalar() or 0
    in_progress_work_orders = db.query(func.count(WorkOrder.id)).filter(
        WorkOrder.status == WorkOrderStatus.IN_PROGRESS
    ).scalar() or 0
    completed_work_orders = db.query(func.count(WorkOrder.id)).filter(
        WorkOrder.status.in_([WorkOrderStatus.COMPLETED, WorkOrderStatus.CLOSED])
    ).scalar() or 0
    total_sales_orders = db.query(func.count(SalesOrder.id)).scalar() or 0
    pending_sales_orders = db.query(func.count(SalesOrder.id)).filter(
        SalesOrder.status.in_([SalesOrderStatus.DRAFT, SalesOrderStatus.PENDING])
    ).scalar() or 0
    total_suppliers = db.query(func.count(Supplier.id)).scalar() or 0

    stats = DashboardStats(
        total_products=total_products,
        total_materials=total_materials,
        total_work_orders=total_work_orders,
        pending_work_orders=pending_work_orders,
        in_progress_work_orders=in_progress_work_orders,
        completed_work_orders=completed_work_orders,
        total_sales_orders=total_sales_orders,
        pending_sales_orders=pending_sales_orders,
        total_suppliers=total_suppliers,
    )

    # 写入缓存，5 分钟过期
    CacheService.set(CACHE_KEYS['dashboard_stats'], stats.model_dump(), ttl=300)

    return stats


# ===========================================
# 操作日志
# ===========================================
@router.get("/audit-logs", response_model=dict)
def list_audit_logs(
    user_id: Optional[int] = Query(None, description="按用户筛选"),
    module: Optional[str] = Query(None, description="按模块筛选"),
    action: Optional[str] = Query(None, description="按操作类型筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN"])),
):
    query = db.query(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if module:
        query = query.filter(AuditLog.module == module)
    if action:
        query = query.filter(AuditLog.action == action)
    total = query.count()
    items = query.order_by(AuditLog.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


# ===========================================
# 用户管理
# ===========================================
@router.get("/users", response_model=dict)
def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN"])),
):
    total = db.query(func.count(User.id)).scalar()
    items = db.query(User).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}

# ===========================================
# 仪表盘 WebSocket 实时推送
# ===========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

manager = ConnectionManager()

@router.websocket("/dashboard/ws")
async def websocket_dashboard(websocket: WebSocket, db: Session = Depends(get_db)):
    await manager.connect(websocket)
    try:
        while True:
            total_products = db.query(func.count(Product.id)).scalar() or 0
            total_materials = db.query(func.count(Material.id)).scalar() or 0
            total_work_orders = db.query(func.count(WorkOrder.id)).scalar() or 0
            pending_work_orders = db.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status.in_([WorkOrderStatus.PLANNED, WorkOrderStatus.NOT_STARTED])
            ).scalar() or 0
            in_progress_work_orders = db.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status == WorkOrderStatus.IN_PROGRESS
            ).scalar() or 0
            completed_work_orders = db.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status.in_([WorkOrderStatus.COMPLETED, WorkOrderStatus.CLOSED])
            ).scalar() or 0
            total_sales_orders = db.query(func.count(SalesOrder.id)).scalar() or 0
            pending_sales_orders = db.query(func.count(SalesOrder.id)).filter(
                SalesOrder.status.in_([SalesOrderStatus.DRAFT, SalesOrderStatus.PENDING])
            ).scalar() or 0
            total_suppliers = db.query(func.count(Supplier.id)).scalar() or 0

            stats = DashboardStats(
                total_products=total_products,
                total_materials=total_materials,
                total_work_orders=total_work_orders,
                pending_work_orders=pending_work_orders,
                in_progress_work_orders=in_progress_work_orders,
                completed_work_orders=completed_work_orders,
                total_sales_orders=total_sales_orders,
                pending_sales_orders=pending_sales_orders,
                total_suppliers=total_suppliers,
            )
            
            await websocket.send_json(stats.model_dump())
            await asyncio.sleep(5) # 每5秒推送一次
    except WebSocketDisconnect:
        manager.disconnect(websocket)
