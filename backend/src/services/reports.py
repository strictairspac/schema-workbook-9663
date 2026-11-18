from sqlalchemy import select
from redis import Redis
from fastapi import HTTPException
from src.models.entities import Relation,Dependency,Report
from src.config.settings import REDIS_URL
from src.constants.enums import RUN_STATES
from .common import snapshot
from src.services import forensics
queue=Redis.from_url(REDIS_URL,decode_responses=True)
def listing(db):return [snapshot(x) for x in db.scalars(select(Report).order_by(Report.id.desc()))]
def detail(db,ident):
    obj=db.get(Report,ident)
    if not obj:raise HTTPException(404,'报告不存在')
    return snapshot(obj)
def create(db,data,user):
    relation=db.get(Relation,data.relation_id)
    if not relation:raise HTTPException(404,'关系不存在')
    # 锁定草案行并串行收集依赖，保证受理瞬间采用的来源版本确定、可核对
    db.execute(select(Relation).where(Relation.id==relation.id).with_for_update())
    deps=list(db.scalars(select(Dependency).where(Dependency.relation_id==relation.id).order_by(Dependency.id).with_for_update()))
    snapshot_data={'relation':snapshot(relation),'dependencies':[snapshot(x) for x in deps]}
    dep_anchors=[]
    for x in deps:
        last=forensics.latest_evidence(db,'dependencies',x.id)
        dep_anchors.append({'id':x.id,'version':x.version,'evidence_hash':last.record_hash if last else None})
    anchors={'relation_id':relation.id,'relation_version':relation.version,
             'relation_evidence_hash':(lambda e:e.record_hash if e else None)(forensics.latest_evidence(db,'relations',relation.id)),
             'dependency_versions':dep_anchors}
    obj=Report(**data.model_dump(),input_snapshot=snapshot_data,status=RUN_STATES[0])
    db.add(obj)
    try:
        db.flush()
        # 报告受理本身入取证链：与并发编辑在同一序号队列里排队，先后可核对
        ev=forensics.append_evidence(db,kind='report_accept',entity_type='reports',entity_id=obj.id,
                                     before_image=None,after_image={'report_id':obj.id,'name':obj.name,
                                                                     'input_snapshot':snapshot_data},
                                     source_anchors=anchors,actor=user.email)
        obj.accept_seq=ev.seq;obj.accept_evidence_hash=ev.record_hash;obj.source_anchors=anchors
        db.commit()
    except Exception:
        db.rollback();raise HTTPException(500,'报告受理取证失败，已整体回滚，请重试')
    try:
        queue.rpush('schemaworkbook:queue',str(obj.id))
    except Exception:
        # 队列不可用：标记失败（取证与受理记录保留，可凭记录追溯后重新受理）
        obj.status='failed';obj.error='队列暂时不可用，请重新创建';db.commit();raise HTTPException(503,obj.error)
    return snapshot(obj)
