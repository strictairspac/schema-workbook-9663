from sqlalchemy import select,func
from fastapi import HTTPException
from src.models.entities import Relation,Dependency
from .common import save_with_evidence,snapshot
def listing(db):return [snapshot(x) for x in db.scalars(select(Dependency).order_by(Dependency.id))]
def validate(db,data,exclude=None):
    relation=db.get(Relation,data.relation_id)
    if not relation:raise HTTPException(404,'关系不存在')
    if not set(data.lhs+data.rhs)<=set(relation.attributes):raise HTTPException(422,'依赖属性必须属于选定关系')
    count=db.scalar(select(func.count()).select_from(Dependency).where(Dependency.relation_id==data.relation_id))
    if not exclude and count>=64:raise HTTPException(422,'最多64条函数依赖，请合并后重试')
def create(db,data,user):
    validate(db,data)
    obj=Dependency(**data.model_dump())
    _,saved=save_with_evidence(db,obj=obj,kind='dependency_create',user=user,action='创建函数依赖')
    return saved
def update(db,ident,data,user):
    obj=db.get(Dependency,ident)
    if not obj:raise HTTPException(404,'依赖不存在')
    validate(db,data,ident)
    before=snapshot(obj)
    for k,v in data.model_dump().items():setattr(obj,k,v)
    obj.version=before['version']+1
    _,saved=save_with_evidence(db,obj=obj,kind='dependency_update',user=user,
                               action='更新函数依赖',before=before)
    return saved
