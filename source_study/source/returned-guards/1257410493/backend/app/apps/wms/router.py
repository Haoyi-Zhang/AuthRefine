from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.apps.auth.dependencies import get_current_user, require_permissions
from app.apps.auth.models import User
from app.apps.wms.models import Inventory, InventoryTransaction, Material, WarehouseLocation
from app.apps.wms.schemas import (
    InventoryResponse, InventoryTransactionResponse, MaterialCreate, MaterialDispatchRequest,
    MaterialReceiveRequest, MaterialReceiveResponse, MaterialResponse, MaterialUpdate,
    StocktakeRequest, WarehouseLocationCreate, WarehouseLocationResponse,
)
from app.apps.wms.services import WMSService

router = APIRouter()


# ===========================================
# 物料管理
# ===========================================
@router.get("/materials", response_model=dict)
def list_materials(
    keyword: Optional[str] = Query(None, description="搜索关键词"),
    category: Optional[str] = Query(None, description="按分类筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Material)
    if keyword:
        query = query.filter(
            (Material.material_code.ilike(f"%{keyword}%"))
            | (Material.name.ilike(f"%{keyword}%"))
        )
    if category:
        query = query.filter(Material.category == category)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/materials", response_model=MaterialResponse)
def create_material(
    request: MaterialCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    existing = db.query(Material).filter(Material.material_code == request.material_code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"物料编码 {request.material_code} 已存在")
    material = Material(**request.model_dump())
    db.add(material)
    db.commit()
    db.refresh(material)
    return material


@router.get("/materials/{material_id}", response_model=MaterialResponse)
def get_material(
    material_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    material = db.query(Material).filter(Material.id == material_id).first()
    if not material:
        raise HTTPException(status_code=404, detail="物料不存在")
    return material


@router.put("/materials/{material_id}", response_model=MaterialResponse)
def update_material(
    material_id: int,
    request: MaterialUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    material = db.query(Material).filter(Material.id == material_id).first()
    if not material:
        raise HTTPException(status_code=404, detail="物料不存在")
    for key, value in request.model_dump(exclude_unset=True).items():
        setattr(material, key, value)
    db.commit()
    db.refresh(material)
    return material


@router.delete("/materials/{material_id}")
def delete_material(
    material_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN"])),
):
    material = db.query(Material).filter(Material.id == material_id).first()
    if not material:
        raise HTTPException(status_code=404, detail="物料不存在")
    db.delete(material)
    db.commit()
    return {"message": "删除成功"}


# ===========================================
# 库存查询
# ===========================================
@router.get("/inventory", response_model=dict)
def list_inventory(
    material_id: Optional[int] = Query(None, description="按物料筛选"),
    product_id: Optional[int] = Query(None, description="按成品筛选"),
    location_code: Optional[str] = Query(None, description="按库位筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Inventory)
    if material_id:
        query = query.filter(Inventory.material_id == material_id)
    if product_id:
        query = query.filter(Inventory.product_id == product_id)
    if location_code:
        query = query.filter(Inventory.location_code == location_code)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


# ===========================================
# 入库操作
# ===========================================
@router.post("/materials/receive", response_model=MaterialReceiveResponse)
def receive_material(
    request: MaterialReceiveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    try:
        inventory = WMSService.receive_material(db, request, current_user.id)
        return MaterialReceiveResponse(
            inventory_id=inventory.id,
            available_qty=inventory.available_qty,
            message="入库成功",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 出库操作
# ===========================================
@router.post("/materials/dispatch")
def dispatch_material(
    request: MaterialDispatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    try:
        inventory = WMSService.dispatch_material(db, request, current_user.id)
        return {"message": "出库成功", "available_qty": inventory.available_qty}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 库存盘点
# ===========================================
@router.post("/inventory/stocktake")
def stocktake(
    request: StocktakeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    try:
        inventory = WMSService.stocktake(db, request, current_user.id)
        return {"message": "盘点完成", "available_qty": inventory.available_qty}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================
# 库存变动日志
# ===========================================
@router.get("/inventory/transactions", response_model=dict)
def list_transactions(
    inventory_id: Optional[int] = Query(None, description="按库存记录筛选"),
    transaction_type: Optional[str] = Query(None, description="按变动类型筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(InventoryTransaction)
    if inventory_id:
        query = query.filter(InventoryTransaction.inventory_id == inventory_id)
    if transaction_type:
        query = query.filter(InventoryTransaction.transaction_type == transaction_type)
    total = query.count()
    items = query.order_by(InventoryTransaction.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


# ===========================================
# 库位管理
# ===========================================
@router.get("/locations", response_model=dict)
def list_locations(
    warehouse_code: Optional[str] = Query(None, description="按仓库筛选"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(WarehouseLocation)
    if warehouse_code:
        query = query.filter(WarehouseLocation.warehouse_code == warehouse_code)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return {"total": total, "items": [{k: v for k, v in item.__dict__.items() if not k.startswith('_')} for item in items]}


@router.post("/locations", response_model=WarehouseLocationResponse)
def create_location(
    request: WarehouseLocationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permissions(["ADMIN", "WMS_USER"])),
):
    location = WarehouseLocation(**request.model_dump())
    db.add(location)
    db.commit()
    db.refresh(location)
    return location
