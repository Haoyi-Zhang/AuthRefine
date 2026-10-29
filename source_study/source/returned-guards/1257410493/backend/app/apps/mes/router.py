from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.apps.auth.dependencies import get_current_user, require_permissions
from app.apps.auth.models import User
from app.apps.mes.models import WorkOrder, WorkOrderProcess
from app.apps.mes.schemas import (
    WorkOrderProcessCreate, WorkOrderProcessResponse,
    WorkOrderReportRequest, WorkOrderReportResponse, WorkOrderResponse,
)
from app.apps.mes.services import MESService

router = APIRouter()


# ===========================================
# 工单管理
# ===========================================
@router.get("/work-orders", response_model=dict)
def list_work_orders(
    status: Optional[str] = Query(None, description="按状态筛选"),
    product_id: Optional[int] = Query(None, description="按产品筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(WorkOrder)
    if status:
        query = query.filter(WorkOrder.status == status)
    if product_id:
        query = query.filter(WorkOrder.product_id == product_id)
    total = query.count()
    items = query.order_by(WorkOrder.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.get("/work-orders/{work_order_id}", response_model=WorkOrderResponse)
def get_work_order(
    work_order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == work_order_id).first()
    if not wo:
        raise HTTPException(status_code=404, detail="工单不存在")
    return wo


@router.post("/work-orders/{work_order_id}/start")
def start_work_order(
    work_order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "MES_USER"])),
):
    """开始生产"""
    try:
        wo = MESService.start_work_order(db, work_order_id)
        return {"message": "工单已开始", "status": wo.status}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/work-orders/{work_order_id}/report", response_model=WorkOrderReportResponse)
def report_production(
    work_order_id: int,
    request: WorkOrderReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "MES_USER"])),
):
    """MES 生产报工 (扣库存、加成品、写溯源)"""
    try:
        trace_ids = MESService.report_production(db, work_order_id, request)
        return WorkOrderReportResponse(
            message="报工成功，库存已更新，溯源已记录",
            traceability_record_ids=trace_ids,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="服务器内部错误或发生并发冲突")


@router.post("/work-orders/{work_order_id}/complete")
def complete_work_order(
    work_order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "MES_USER"])),
):
    """完成工单"""
    try:
        wo = MESService.complete_work_order(db, work_order_id)
        return {"message": "工单已完成", "status": wo.status}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/work-orders/{work_order_id}/close")
def close_work_order(
    work_order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "MES_USER"])),
):
    """关闭工单"""
    try:
        wo = MESService.close_work_order(db, work_order_id)
        return {"message": "工单已关闭", "status": wo.status}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 工序管理
# ===========================================
@router.get("/work-orders/{work_order_id}/processes", response_model=dict)
def list_processes(
    work_order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == work_order_id).first()
    if not wo:
        raise HTTPException(status_code=404, detail="工单不存在")
    processes = (
        db.query(WorkOrderProcess)
        .filter(WorkOrderProcess.work_order_id == work_order_id)
        .order_by(WorkOrderProcess.sequence)
        .all()
    )
    return {"total": len(processes), "items": processes}


@router.post("/work-orders/{work_order_id}/processes", response_model=WorkOrderProcessResponse)
def create_process(
    work_order_id: int,
    request: WorkOrderProcessCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "MES_USER"])),
):
    wo = db.query(WorkOrder).filter(WorkOrder.id == work_order_id).first()
    if not wo:
        raise HTTPException(status_code=404, detail="工单不存在")
    process = WorkOrderProcess(work_order_id=work_order_id, **request.model_dump())
    db.add(process)
    db.commit()
    db.refresh(process)
    return process
