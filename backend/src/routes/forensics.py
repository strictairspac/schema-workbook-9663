import json
from fastapi import APIRouter,Depends
from fastapi.responses import Response
from sqlalchemy import select
from src.config.database import db_session
from src.utils.security import current,admin
from src.models.entities import ChangeEvidence,Report,Audit
from src.services import forensics
from src.services.common import snapshot
router=APIRouter()

@router.get('/forensics/chain')
def chain(db=Depends(db_session),user=Depends(current)):
    """在线核验取证链：返回整体状态（待核验/可信/损坏）与断裂定位序号。"""
    status=forensics.chain_status(db)
    records=[forensics.record_payload(x) for x in db.scalars(select(ChangeEvidence).order_by(ChangeEvidence.seq))]
    legacy=[snapshot(x) for x in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(100))]
    return {**status,'records':records,'legacy_audit_logs':legacy,
            'public_key_pem':forensics.public_key_pem(),'genesis_hash':forensics.GENESIS_HASH}

@router.get('/forensics/credential')
def credential_head(db=Depends(db_session),user=Depends(current)):
    """全链凭证：固定在当前已提交链首（head）时点；后续正常修改不使旧凭证失效。"""
    meta=db.get(forensics.ChainMeta,1)
    if meta is None or meta.head_seq==0:return Response('{"detail":"尚无可导出的取证记录"}',status_code=409,media_type='application/json')
    bundle=forensics.build_credential(db,head_seq=meta.head_seq,name='全链变更凭证',subject={'type':'chain','head_seq':meta.head_seq})
    return _file_response(bundle,f'credential-chain-seq{meta.head_seq}.json')

@router.get('/reports/{ident}/credential')
def report_credential(ident:int,db=Depends(db_session),user=Depends(current)):
    """报告受理凭证：固定在该报告受理（入队冻结）的同一已提交时点。"""
    report=db.get(Report,ident)
    if not report:return Response('{"detail":"报告不存在"}',status_code=404,media_type='application/json')
    if not report.accept_seq:return Response('{"detail":"该报告产生于取证功能上线前，无受理凭证"}',status_code=409,media_type='application/json')
    bundle=forensics.build_credential(db,head_seq=report.accept_seq,
                                      name=f'报告受理凭证 #{ident}',subject={'type':'report','report_id':ident})
    return _file_response(bundle,f'credential-report-{ident}-seq{report.accept_seq}.json')

@router.get('/forensics/public-key')
def public_key(db=Depends(db_session),user=Depends(current)):
    return {'public_key_pem':forensics.public_key_pem(),'algorithm':'Ed25519'}

def _file_response(bundle,filename):
    body=json.dumps(bundle,ensure_ascii=False,indent=2)
    return Response(body,media_type='application/json',
                    headers={'Content-Disposition':f'attachment; filename="{filename}"'})
