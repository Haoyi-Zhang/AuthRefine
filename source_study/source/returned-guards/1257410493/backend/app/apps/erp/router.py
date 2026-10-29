import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from celery.result import AsyncResult
from app.celery_app import celery_app
from app.tasks.report import generate_report
from app.core.database import get_db
from app.core.redis import CacheService, CACHE_KEYS
from app.apps.auth.dependencies import get_current_user, require_permissions as require_roles
from app.apps.auth.models import User
from app.apps.erp.models import BOM, Product, PurchaseOrder, SalesOrder, Supplier
from app.apps.erp.schemas import (
    BOMCreate, BOMResponse, ProductCreate, ProductResponse, ProductUpdate,
    PurchaseOrderCreate, PurchaseOrderResponse, SalesOrderCreate, SalesOrderResponse,
    SalesOrderUpdate, SupplierCreate, SupplierResponse, SupplierUpdate,
    WorkOrderCreateRequest, WorkOrderCreateResponse,
)
from app.apps.erp.services import ERPService

router = APIRouter()


# ===========================================
# 产品管理
# ===========================================
@router.get("/products", response_model=dict)
def list_products(
    skip: int = 0,
    limit: int = 100,
    keyword: Optional[str] = Query(None, description="搜索关键词"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 尝试从缓存获取（仅无搜索关键词时）
    if not keyword:
        cache_key = f"{CACHE_KEYS['products_list']}:{skip}:{limit}"
        cached = CacheService.get(cache_key)
        if cached:
            return cached

    query = db.query(Product)
    if keyword:
        query = query.filter(
            (Product.product_code.ilike(f"%{keyword}%"))
            | (Product.name.ilike(f"%{keyword}%"))
        )
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    result = {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}

    # 写入缓存（无搜索关键词时）
    if not keyword:
        cache_key = f"{CACHE_KEYS['products_list']}:{skip}:{limit}"
        CacheService.set(cache_key, result, ttl=300)

    return result


@router.post("/products", response_model=ProductResponse)
def create_product(
    request: ProductCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        result = ERPService.create_product(db, request)
        CacheService.delete_pattern(f"{CACHE_KEYS['products_list']}:*")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/products/{product_id}", response_model=ProductResponse)
def get_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="产品不存在")
    return product


@router.put("/products/{product_id}", response_model=ProductResponse)
def update_product(
    product_id: int,
    request: ProductUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.update_product(db, product_id, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/products/{product_id}")
def delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN"])),
):
    try:
        ERPService.delete_product(db, product_id)
        CacheService.delete_pattern(f"{CACHE_KEYS['products_list']}:*")
        CacheService.delete(CACHE_KEYS['product_detail'].format(id=product_id))
        return {"message": "删除成功"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# BOM 管理
# ===========================================
@router.get("/boms", response_model=dict)
def list_boms(
    product_id: Optional[int] = Query(None, description="按产品筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(BOM)
    if product_id:
        query = query.filter(BOM.product_id == product_id)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/boms", response_model=BOMResponse)
def create_bom(
    request: BOMCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.create_bom(db, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/boms/{bom_id}", response_model=BOMResponse)
def get_bom(
    bom_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    bom = db.query(BOM).filter(BOM.id == bom_id).first()
    if not bom:
        raise HTTPException(status_code=404, detail="BOM 不存在")
    return bom


@router.post("/boms/{bom_id}/activate", response_model=BOMResponse)
def activate_bom(
    bom_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.activate_bom(db, bom_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 销售订单管理
# ===========================================
@router.get("/sales-orders", response_model=dict)
def list_sales_orders(
    status: Optional[str] = Query(None, description="按状态筛选"),
    keyword: Optional[str] = Query(None, description="搜索关键词"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(SalesOrder)
    if status:
        query = query.filter(SalesOrder.status == status)
    if keyword:
        query = query.filter(
            (SalesOrder.order_number.ilike(f"%{keyword}%"))
            | (SalesOrder.customer_name.ilike(f"%{keyword}%"))
        )
    total = query.count()
    items = query.order_by(SalesOrder.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/sales-orders", response_model=SalesOrderResponse)
def create_sales_order(
    request: SalesOrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.create_sales_order(db, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sales-orders/{order_id}", response_model=SalesOrderResponse)
def get_sales_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    order = db.query(SalesOrder).filter(SalesOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="销售订单不存在")
    return order


@router.put("/sales-orders/{order_id}", response_model=SalesOrderResponse)
def update_sales_order(
    order_id: int,
    request: SalesOrderUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.update_sales_order(db, order_id, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sales-orders/{order_id}/confirm", response_model=SalesOrderResponse)
def confirm_sales_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.confirm_sales_order(db, order_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sales-orders/{order_id}/ship", response_model=SalesOrderResponse)
def ship_sales_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.ship_sales_order(db, order_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sales-orders/{order_id}/cancel", response_model=SalesOrderResponse)
def cancel_sales_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.cancel_sales_order(db, order_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 供应商管理
# ===========================================
@router.get("/suppliers", response_model=dict)
def list_suppliers(
    status: Optional[str] = Query(None, description="按状态筛选"),
    keyword: Optional[str] = Query(None, description="搜索关键词"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Supplier)
    if status:
        query = query.filter(Supplier.status == status)
    if keyword:
        query = query.filter(
            (Supplier.code.ilike(f"%{keyword}%"))
            | (Supplier.name.ilike(f"%{keyword}%"))
        )
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/suppliers", response_model=SupplierResponse)
def create_supplier(
    request: SupplierCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.create_supplier(db, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/suppliers/{supplier_id}", response_model=SupplierResponse)
def get_supplier(
    supplier_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    supplier = db.query(Supplier).filter(Supplier.id == supplier_id).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="供应商不存在")
    return supplier


@router.put("/suppliers/{supplier_id}", response_model=SupplierResponse)
def update_supplier(
    supplier_id: int,
    request: SupplierUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.update_supplier(db, supplier_id, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/suppliers/{supplier_id}")
def delete_supplier(
    supplier_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN"])),
):
    try:
        ERPService.delete_supplier(db, supplier_id)
        return {"message": "删除成功"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 采购订单管理
# ===========================================
@router.get("/purchase-orders", response_model=dict)
def list_purchase_orders(
    status: Optional[str] = Query(None, description="按状态筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(PurchaseOrder)
    if status:
        query = query.filter(PurchaseOrder.status == status)
    total = query.count()
    items = query.order_by(PurchaseOrder.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/purchase-orders", response_model=PurchaseOrderResponse)
def create_purchase_order(
    request: PurchaseOrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        return ERPService.create_purchase_order(db, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/purchase-orders/{po_id}", response_model=PurchaseOrderResponse)
def get_purchase_order(
    po_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    po = db.query(PurchaseOrder).filter(PurchaseOrder.id == po_id).first()
    if not po:
        raise HTTPException(status_code=404, detail="采购订单不存在")
    return po


# ===========================================
# 工单创建（ERP 下发）
# ===========================================
@router.post("/work-orders/create", response_model=WorkOrderCreateResponse)
def create_work_order(
    request: WorkOrderCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    try:
        wo = ERPService.create_work_order(db, request)
        return WorkOrderCreateResponse(
            work_order_id=wo.id,
            work_order_number=wo.work_order_number,
            message="工单下发成功",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 报表生成管理 (Celery 异步任务)
# ===========================================
@router.get("/reports/financial/{order_id}")
def generate_financial_report(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "ERP_USER"])),
):
    """触发异步财务报告生成任务"""
    # 验证订单是否存在
    order = db.query(SalesOrder).filter(SalesOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="销售订单不存在")
    
    # 触发 celery 任务
    task = generate_report.delay(order_id)
    return {"task_id": task.id, "status": "PENDING"}


@router.get("/reports/status/{task_id}")
def get_report_status(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    """查询财务报告生成任务的状态并获取下载链接"""
    task_result = AsyncResult(task_id, app=celery_app)
    
    result_data = {
        "task_id": task_id,
        "status": task_result.status,
    }
    
    if task_result.status == "SUCCESS":
        file_path = task_result.result
        if file_path:
            filename = os.path.basename(file_path)
            result_data["download_url"] = f"/api/v1/erp/reports/download/{filename}"
    elif task_result.status == "FAILURE":
        result_data["error"] = str(task_result.info)
        
    return result_data


@router.get("/reports/download/{filename}")
def download_report(
    filename: str,
    current_user: User = Depends(get_current_user),
):
    """下载生成的 PDF 报告"""
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="无效的文件名")
        
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "reports")
    )
    file_path = os.path.join(reports_dir, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="报告文件不存在")
        
    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename=filename
    )
