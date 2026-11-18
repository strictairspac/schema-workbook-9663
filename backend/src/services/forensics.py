import os,json,hashlib,hmac
from datetime import datetime,timezone
from fastapi import HTTPException
from sqlalchemy import select,update
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from src.config.settings import EVIDENCE_SECRET
from src.models.entities import ChangeEvidence,ChainMeta
from src.constants.enums import EVIDENCE_KINDS

GENESIS_HASH='0'*64
GENESIS_SEQ=0

def canonical(value):
    """与前端/离线脚本逐字节一致的规范 JSON：键排序、无空白、非 ASCII 原样输出。"""
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')

def compute_record_hash(*,seq,kind,entity_type,entity_id,before_image,after_image,source_anchors,actor,occurred_at,prev_hash):
    """取证记录哈希：所有字段按固定次序拼接，规范 JSON 后 SHA256。三方实现必须保持一致。"""
    payload={'seq':seq,'kind':kind,'entity_type':entity_type,'entity_id':entity_id,
             'before_image':before_image,'after_image':after_image,'source_anchors':source_anchors,
             'actor':actor,'occurred_at':occurred_at,'prev_hash':prev_hash}
    return hashlib.sha256(canonical(payload).encode('utf-8')).hexdigest()

def record_payload(ev):
    return {'seq':ev.seq,'kind':ev.kind,'entity_type':ev.entity_type,'entity_id':ev.entity_id,
            'before_image':ev.before_image,'after_image':ev.after_image,'source_anchors':ev.source_anchors,
            'actor':ev.actor,'occurred_at':ev.occurred_at,'prev_hash':ev.prev_hash,'record_hash':ev.record_hash}

# ---------- 签名密钥：由 EVIDENCE_SECRET 确定性派生 Ed25519，离线侧只需公钥即可验签 ----------
_private_key=None
def signing_key():
    global _private_key
    if _private_key is None:
        seed=hashlib.sha256(('ed25519|'+EVIDENCE_SECRET).encode('utf-8')).digest()
        _private_key=Ed25519PrivateKey.from_private_bytes(seed)
    return _private_key

def public_key_pem():
    return signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

def verify_signature(public_key_pem_text,message,signature_hex):
    pub=serialization.load_pem_public_key(public_key_pem_text.encode('ascii'))
    if not isinstance(pub,Ed25519PublicKey):raise ValueError('仅支持 Ed25519 公钥')
    pub.verify(bytes.fromhex(signature_hex),message)

def latest_evidence(db,entity_type,entity_id):
    """取某实体最近一次成功修改的取证记录（即当前版本的来源）。"""
    return db.scalars(select(ChangeEvidence)
                      .where(ChangeEvidence.entity_type==entity_type,ChangeEvidence.entity_id==entity_id)
                      .order_by(ChangeEvidence.seq.desc())).first()

def append_evidence(db,*,kind,entity_type,entity_id,before_image,after_image,source_anchors,actor):
    """在同一业务事务内追加一条取证记录并分配全局序号。

    依赖 ChainMeta 单行行锁串行化并发提交；任一步失败抛出异常，由业务层整体回滚。
    """
    if kind not in EVIDENCE_KINDS:raise ValueError('未知取证动作 '+str(kind))
    meta=db.get(ChainMeta,1)
    if meta is None:
        meta=ChainMeta(id=1,head_seq=GENESIS_SEQ,head_hash=GENESIS_HASH);db.add(meta);db.flush()
    # 原子自增并取得行锁（InnoDB 行锁 / SQLite WAL 写锁）：并发编辑与报告受理在此串行，
    # 序号全局连续、先后可核对，不会出现重号或缺号
    db.execute(update(ChainMeta).where(ChainMeta.id==1).values(head_seq=ChainMeta.head_seq+1))
    db.flush()
    meta=db.get(ChainMeta,1)
    seq=meta.head_seq
    occurred_at=utc_now_iso()
    prev_hash=meta.head_hash
    record_hash=compute_record_hash(seq=seq,kind=kind,entity_type=entity_type,entity_id=entity_id,
                                    before_image=before_image,after_image=after_image,
                                    source_anchors=source_anchors,actor=actor,
                                    occurred_at=occurred_at,prev_hash=prev_hash)
    ev=ChangeEvidence(seq=seq,kind=kind,entity_type=entity_type,entity_id=entity_id,
                      before_image=before_image,after_image=after_image,source_anchors=source_anchors,
                      actor=actor,occurred_at=occurred_at,prev_hash=prev_hash,record_hash=record_hash)
    db.add(ev);db.flush()
    meta.head_seq=seq;meta.head_hash=record_hash
    return ev

# ---------- 链核验：重算每条哈希并核对链接，定位第一个断裂处 ----------
def verify_chain(records):
    """records: 按 seq 升序的 ChangeEvidence 列表。返回 (状态, 断裂序号或None, 明细)。"""
    prev_hash=GENESIS_HASH;expected_seq=GENESIS_SEQ+1;break_seq=None
    checks=[]
    for ev in records:
        ok_link=(ev.prev_hash==prev_hash)
        ok_seq=(ev.seq==expected_seq)
        recomputed=compute_record_hash(seq=ev.seq,kind=ev.kind,entity_type=ev.entity_type,entity_id=ev.entity_id,
                                        before_image=ev.before_image,after_image=ev.after_image,
                                        source_anchors=ev.source_anchors,actor=ev.actor,
                                        occurred_at=ev.occurred_at,prev_hash=ev.prev_hash)
        ok_hash=hmac.compare_digest(recomputed,ev.record_hash)
        ok=ok_link and ok_seq and ok_hash
        checks.append({'seq':ev.seq,'ok':ok,'reason':None if ok else _reason(ok_seq,ok_link,ok_hash)})
        if not ok and break_seq is None:break_seq=ev.seq
        if not ok:break
        prev_hash=ev.record_hash;expected_seq+=1
    if not records:return 'pending',None,[]
    if break_seq is not None:return 'damaged',break_seq,checks
    return 'trusted',None,checks

def _reason(ok_seq,ok_link,ok_hash):
    if not ok_seq:return '序号不连续，存在删尾或乱序'
    if not ok_link:return '前向哈希不匹配，链在该处断裂'
    return '记录哈希重算不一致，内容被篡改'

def chain_status(db):
    records=list(db.scalars(select(ChangeEvidence).order_by(ChangeEvidence.seq)))
    state,break_seq,checks=verify_chain(records)
    return {'state':state,'break_seq':break_seq,'length':len(records),
            'head_seq':records[-1].seq if records else 0,
            'head_hash':records[-1].record_hash if records else GENESIS_HASH,'checks':checks}

# ---------- 下载凭证：固定在某一已提交时点（head_seq），之后的正常修改不使其失效 ----------
def build_credential(db,*,head_seq,name,subject):
    records=list(db.scalars(select(ChangeEvidence).where(ChangeEvidence.seq<=head_seq).order_by(ChangeEvidence.seq)))
    if not records or records[-1].seq!=head_seq:
        raise HTTPException(409,'凭证时点尚未提交或已被删除，无法固定凭证')
    ev_payloads=[record_payload(x) for x in records]
    manifest={'schema_version':1,'subject':subject,'credential_name':name,
              'pinned_seq':head_seq,'pinned_hash':records[-1].record_hash,
              'genesis_hash':GENESIS_HASH,'records':ev_payloads}
    message=canonical(manifest).encode('utf-8')
    signature=signing_key().sign(message).hex()
    return {'format':'nanlu-change-credential/v1','manifest':manifest,
            'signature_algorithm':'Ed25519','signature':signature,
            'public_key_pem':public_key_pem(),
            'verification_hint':'离线核验：重算每条 record_hash 并按 prev_hash 链接，再用 public_key_pem 校验 signature；签名消息为 manifest 的规范 JSON（键排序、无空白）'}

def verify_credential_bundle(bundle,*,public_key_pem_text=None):
    """离线/在线通用核验：检出内容篡改、乱序与删尾。不依赖数据库当前状态。"""
    errors=[]
    try:
        manifest=bundle['manifest'];records=manifest['records']
    except (KeyError,TypeError):raise ValueError('凭证结构缺少 manifest/records')
    # 1) 签名核验（提供公钥时）
    sig_ok=False
    pem=public_key_pem_text or bundle.get('public_key_pem')
    if pem:
        try:
            verify_signature(pem,canonical(manifest).encode('utf-8'),bundle['signature']);sig_ok=True
        except Exception as e:errors.append('签名核验失败：'+str(e))
    else:errors.append('未提供公钥，仅执行链内哈希核验，无法证明凭证来源')
    # 2) 链内核验：哈希、链接、序号连续性（乱序/删尾）、固定时点一致
    prev=GENESIS_HASH;expected=GENESIS_SEQ+1;break_seq=None
    for ev in records:
        recomputed=compute_record_hash(seq=ev['seq'],kind=ev['kind'],entity_type=ev['entity_type'],
                                       entity_id=ev['entity_id'],before_image=ev['before_image'],
                                       after_image=ev['after_image'],source_anchors=ev['source_anchors'],
                                       actor=ev['actor'],occurred_at=ev['occurred_at'],prev_hash=ev['prev_hash'])
        if ev['seq']!=expected:
            errors.append(f"序号乱序/删尾：期望 seq={expected}，实际 seq={ev['seq']}");break_seq=break_seq or ev['seq'];break
        if ev['prev_hash']!=prev:
            errors.append(f"链断裂于 seq={ev['seq']}：prev_hash 不匹配");break_seq=break_seq or ev['seq'];break
        if not hmac.compare_digest(recomputed,ev['record_hash']):
            errors.append(f"内容篡改于 seq={ev['seq']}：record_hash 重算不一致");break_seq=break_seq or ev['seq'];break
        prev=ev['record_hash'];expected+=1
    if records and manifest.get('pinned_seq')!=records[-1]['seq']:
        errors.append('固定时点与凭证末条记录不一致')
    if records and manifest.get('pinned_hash')!=records[-1]['record_hash']:
        errors.append('固定时点哈希与凭证末条记录不一致')
    return {'valid':not errors,'signature_verified':sig_ok,'break_seq':break_seq,
            'records_checked':len(records),'pinned_seq':manifest.get('pinned_seq'),'errors':errors}
