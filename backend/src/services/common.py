from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from datetime import datetime,timezone
from src.models.entities import Audit
from src.services import forensics

def snapshot(obj):
    """实体镜像：返回所有列的当前值，datetime 统一转 ISO8601 字符串。

    可传入 ORM 对象或变更前的字典镜像；同时用于 API 响应与 JSON 取证列，保证可序列化。
    """
    if obj is None:return None
    if isinstance(obj,dict):
        return {k:(_iso(v) if isinstance(v,datetime) else v) for k,v in obj.items()}
    return {col.name:_iso(getattr(obj,col.name)) for col in obj.__table__.columns}

def _iso(value):
    if isinstance(value,datetime):
        if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return value

def save_with_evidence(db,*,obj,kind,user,action,before=None,source_anchors=None):
    """业务修改 + 审计 + 变更取证在同一事务提交。

    取证记录写入失败（含序号分配、唯一约束等）时 rollback，业务修改整体不生效。
    返回 (取证记录 payload, 变更后镜像)。
    """
    db.add(obj)
    try:
        db.flush()  # 先拿到实体 id / 触发唯一约束校验
    except IntegrityError:
        db.rollback();raise HTTPException(409,'编号已存在或引用对象无效，请调整后重试')
    before_image=snapshot(before)
    after_image=snapshot(obj)
    try:
        ev=forensics.append_evidence(db,kind=kind,entity_type=obj.__tablename__,entity_id=obj.id,
                                     before_image=before_image,after_image=after_image,
                                     source_anchors=source_anchors,actor=user.email)
        db.add(Audit(actor=user.email,action=action))
        db.commit()
    except Exception:
        db.rollback();raise HTTPException(500,'变更取证写入失败，业务修改已整体回滚，请重试')
    return forensics.record_payload(ev),after_image
