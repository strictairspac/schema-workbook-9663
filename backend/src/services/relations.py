from sqlalchemy import select
from fastapi import HTTPException
from src.models.entities import Relation,Dependency
from .common import save_with_evidence,snapshot
def listing(db):
    return [snapshot(x) for x in db.scalars(select(Relation).order_by(Relation.id))]
def create(db,data,user):
    obj=Relation(**data.model_dump())
    _,saved=save_with_evidence(db,obj=obj,kind='relation_create',user=user,action='创建关系草案 '+data.code)
    return saved
def update(db,ident,data,user):
    obj=db.get(Relation,ident)
    if not obj:raise HTTPException(404,'关系不存在')
    before=snapshot(obj)
    deps=list(db.scalars(select(Dependency).where(Dependency.relation_id==ident)))
    if any(not set(x.lhs+x.rhs)<=set(data.attributes) for x in deps):raise HTTPException(422,'现有依赖引用被移除属性，请先修改依赖')
    for k,v in data.model_dump().items():setattr(obj,k,v)
    obj.version=before['version']+1
    _,saved=save_with_evidence(db,obj=obj,kind='relation_update',user=user,
                               action='更新关系草案 '+data.code,before=before)
    return saved
