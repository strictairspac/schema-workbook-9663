"""变更取证端到端集成测试（SQLite 内存库，无需 MySQL/Redis）。

覆盖验收点：
1. 成功修改保留前后内容/操作者；取证写入失败时业务整体回滚
2. 并发改依赖与报告受理：行锁串行、序号连续、来源版本可核对
3. 凭证固定在已提交时点；后续修改不使旧凭证失效
4. 离线核验检出内容篡改、乱序、删尾
5. 页面状态：待核验 → 可信 / 损坏，并定位断裂序号
6. 历史审计记录标记为无法追溯
"""
import os,sys,json,copy,threading
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DATABASE_URL','sqlite://')  # 测试使用内存 SQLite，不依赖 MySQL

from sqlalchemy import create_engine,event
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

import src.config.database as dbmod
from src.config.database import Base
from src.models import entities
from src.models.entities import User,Relation,Dependency,ChangeEvidence,ChainMeta,Audit
from src.services import reports as reports_service
from src.services import forensics
from src.utils.security import password_hash
from scripts.verify_credential import verify as offline_verify

# ---- 文件型 SQLite + WAL，模拟真实并发写；busy_timeout 让锁等待而非立即失败 ----
import glob
from sqlalchemy import text
TEST_DB='/tmp/schemaworkbook-forensics-test.db'
for f in glob.glob(TEST_DB+'*'):
    os.remove(f)
engine=create_engine('sqlite:///'+TEST_DB,connect_args={'timeout':30,'check_same_thread':False})
# 事件中只设 busy_timeout（不改变事务状态）；journal_mode 在 DDL 之后持久化切换，
# 避免 WAL 切换的隐式提交干扰 create_all 的 DDL 事务
@event.listens_for(engine,'connect')
def _sqlite_pragmas(dbapi_conn,_):
    dbapi_conn.cursor().execute('PRAGMA busy_timeout=30000')
TestSession=sessionmaker(engine,expire_on_commit=False)
dbmod.engine=engine;dbmod.Session=TestSession
Base.metadata.create_all(engine)
with engine.begin() as _c:
    _c.execute(text('PRAGMA journal_mode=WAL'))
def reset_schema():
    """drop/create 后 dispose 连接池，避免旧 ChainMeta 行缓存导致序号重号。WAL 为库级持久属性，重建后保留。"""
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine);engine.dispose()

class _FakeRedis:
    def __init__(self):self.items=[]
    def rpush(self,k,v):self.items.append(v)
    def ping(self):return True
reports_service.queue=_FakeRedis()

from src.main import app
from src.config.database import db_session
def _override():
    db=TestSession()
    try:yield db
    finally:db.close()
app.dependency_overrides[db_session]=_override

client=TestClient(app)
PASS=0;FAIL=0
def check(name,cond,detail=''):
    global PASS,FAIL
    if cond:PASS+=1;print(f'  PASS  {name}')
    else:FAIL+=1;print(f'  FAIL  {name}  {detail}')

def login(role):
    r=client.post('/auth/login',json={'email':f'{role}@nanlu.test','password':'Demo2026!'})
    assert r.status_code==200,r.text
    return {'Authorization':'Bearer '+r.json()['token']}

def setup_data():
    Base.metadata.create_all(engine)
    with TestSession() as db:
        rel=Relation(code='NL-T-1',title='集成测试委托单',attributes=['委托号','客户','检测项','方法'],note='初始')
        db.add(rel);db.commit()
        return rel.id

REL_ID=None
OP=None;ADMIN=None;VIEWER=None

def ensure_users():
    Base.metadata.create_all(engine)
    with TestSession() as db:
        for role in ('admin','operator','viewer'):
            email=f'{role}@nanlu.test'
            if not db.query(User).filter_by(email=email).first():
                db.add(User(email=email,password=password_hash('Demo2026!'),role=role))
        if not db.query(Audit).filter_by(action='历史Excel迁移：批量导入委托单草案').first():
            db.add(Audit(actor='admin@nanlu.test',action='历史Excel迁移：批量导入委托单草案'))
        db.commit()

def test_crud_evidence_and_rollback():
    print('\n[1] 成功修改取证（前后内容/操作者）+ 取证失败整体回滚')
    global REL_ID
    REL_ID=setup_data()
    # 创建依赖
    r=client.post('/dependencies',headers=OP,
                  json={'relation_id':REL_ID,'lhs':['委托号'],'rhs':['客户'],'note':'业务规则1'})
    check('创建依赖 201',r.status_code==201,r.text)
    dep_id=r.json()['id'];check('依赖初始 version=1',r.json()['version']==1)
    # 修改依赖
    r=client.put(f'/dependencies/{dep_id}',headers=OP,
                 json={'relation_id':REL_ID,'lhs':['检测项'],'rhs':['方法'],'note':'业务规则2'})
    check('修改依赖 200',r.status_code==200,r.text)
    check('依赖 version 递增为2',r.json()['version']==2)
    # 取证链记录
    chain=client.get('/forensics/chain',headers=OP).json()
    check('链状态可信',chain['state']=='trusted',chain['state'])
    check('已有2条取证记录',chain['length']==2,str(chain['length']))
    kinds=[x['kind'] for x in chain['records']]
    check('动作类别正确',kinds==['dependency_create','dependency_update'],str(kinds))
    upd=chain['records'][1]
    check('操作者留痕',upd['actor']=='operator@nanlu.test',upd['actor'])
    check('前镜像保留旧 lhs',upd['before_image']['lhs']==['委托号'],str(upd['before_image']))
    check('后镜像保留新 lhs',upd['after_image']['lhs']==['检测项'],str(upd['after_image']))
    check('前镜像 version=1',upd['before_image']['version']==1)
    check('哈希链链接正确',upd['prev_hash']==chain['records'][0]['record_hash'])
    # viewer 禁止写
    r=client.post('/dependencies',headers=VIEWER,
                  json={'relation_id':REL_ID,'lhs':['委托号'],'rhs':['方法'],'note':'x'})
    check('观察员写入被拒 403',r.status_code==403,str(r.status_code))
    # 取证写入失败 → 业务整体回滚：破坏 ChainMeta 唯一序号推进，模拟提交异常
    with TestSession() as db:
        before_dep=db.get(Dependency,dep_id).note
        before_count=db.query(ChangeEvidence).count()
    orig=forensics.append_evidence
    def boom(*a,**k):raise RuntimeError('模拟取证存储故障')
    forensics.append_evidence=boom
    try:
        r=client.put(f'/dependencies/{dep_id}',headers=OP,
                     json={'relation_id':REL_ID,'lhs':['检测项'],'rhs':['方法'],'note':'应回滚的备注'})
        check('取证失败返回 500',r.status_code==500,str(r.status_code))
    finally:
        forensics.append_evidence=orig
    with TestSession() as db:
        after_dep=db.get(Dependency,dep_id).note
        after_count=db.query(ChangeEvidence).count()
        after_ver=db.get(Dependency,dep_id).version
    check('业务备注已回滚',after_dep==before_dep== '业务规则2',f'{after_dep}!={before_dep}')
    check('取证记录数量未增加',after_count==before_count==2,f'{after_count}/{before_count}')
    check('实体版本未递增',after_ver==2,str(after_ver))
    # 唯一约束冲突路径仍可正常工作
    r=client.post('/relations',headers=OP,
                  json={'code':'NL-T-1','title':'重复编号','attributes':['A'],'note':''})
    check('重复草案编号 409',r.status_code==409,str(r.status_code))

def test_concurrent_edits_and_acceptance():
    print('\n[2] 并发改依赖 + 报告受理：串行化、序号连续、来源版本核对')
    # 准备两条依赖
    created=[]
    for lhs,rhs in [(['委托号'],['客户']),(['检测项'],['方法'])]:
        r=client.post('/dependencies',headers=OP,
                      json={'relation_id':REL_ID,'lhs':lhs,'rhs':rhs,'note':'并发前'})
        created.append(r.json()['id'])
    barrier=threading.Barrier(3)
    results=[];lock=threading.Lock()
    def edit_dep(dep_id,note):
        h=login('operator')
        barrier.wait()
        r=client.put(f'/dependencies/{dep_id}',headers=h,
                     json={'relation_id':REL_ID,'lhs':['委托号'],'rhs':['客户'],'note':note})
        with lock:results.append(('edit',dep_id,note,r.status_code))
    def accept_report(name):
        h=login('admin')
        barrier.wait()
        r=client.post('/reports',headers=h,json={'name':name,'relation_id':REL_ID})
        with lock:results.append(('report',name,r.status_code,r.json() if r.status_code==201 else r.text))
    t1=threading.Thread(target=edit_dep,args=(created[0],'并发修改-A'))
    t2=threading.Thread(target=edit_dep,args=(created[1],'并发修改-B'))
    t3=threading.Thread(target=accept_report,args=('并发受理任务',))
    for t in (t1,t2,t3):t.start()
    for t in (t1,t2,t3):t.join()
    ok_status=lambda x:x[3] if x[0]=='edit' else x[2]
    check('三个并发请求全部成功',all(ok_status(x) in (200,201) for x in results),str([(x[0],ok_status(x)) for x in results]))
    check('两个编辑与一次受理均落库',sorted(x[0] for x in results)==['edit','edit','report'])
    chain=client.get('/forensics/chain',headers=ADMIN).json()
    seqs=[x['seq'] for x in chain['records']]
    check('全局序号连续无缺号',seqs==list(range(1,len(seqs)+1)),str(seqs))
    check('并发后链仍可信',chain['state']=='trusted',chain['state'])
    # 报告受理记录与来源锚点
    accept=[x for x in chain['records'] if x['kind']=='report_accept']
    check('存在受理取证',len(accept)==1,str(len(accept)))
    acc=accept[0]
    anchors=acc['source_anchors']
    check('来源含草案版本',anchors['relation_version']>=1)
    # 受理时该草案下的全部依赖（含测试1遗留的依赖）都应进入来源锚点
    with TestSession() as db:
        expected_dep_ids={d.id for d in db.query(Dependency).filter_by(relation_id=REL_ID).all()}
    check('来源含全部依赖版本',{d['id'] for d in anchors['dependency_versions']}==expected_dep_ids)
    check('来源含依赖取证哈希',all(d['evidence_hash'] for d in anchors['dependency_versions']))
    # 每个来源哈希必须指向链上真实存在、且当时已提交的取证记录（并发先后可核对）
    chain_hashes={x['record_hash']:x for x in chain['records']}
    anchored=[chain_hashes[d['evidence_hash']] for d in anchors['dependency_versions']]
    check('来源锚点全部落在已提交取证链上',len(anchored)==len(expected_dep_ids))
    check('来源取证均早于或等于受理序号',all(x['seq']<=acc['seq'] for x in anchored),
          str([(x['seq'],acc['seq']) for x in anchored]))
    # 受理快照中的依赖版本必须与锚点版本一致
    snap_versions={d['id']:d['version'] for d in acc['after_image']['input_snapshot']['dependencies']}
    check('冻结快照版本与来源锚点一致',
          snap_versions=={d['id']:d['version'] for d in anchors['dependency_versions']})
    # 受理快照冻结：受理后再改依赖，报告 input_snapshot 不变
    report_id=[x for x in results if x[0]=='report'][0][3]['id']
    snap_before=client.get(f'/reports/{report_id}',headers=OP).json()['input_snapshot']
    client.put(f'/dependencies/{created[0]}',headers=OP,
               json={'relation_id':REL_ID,'lhs':['委托号'],'rhs':['客户'],'note':'受理之后再改'})
    snap_after=client.get(f'/reports/{report_id}',headers=OP).json()['input_snapshot']
    check('受理后修改不影响已冻结快照',snap_before==snap_after)
    # 受理时点与链首的先后核对：受理 seq 之后还有新记录
    chain2=client.get('/forensics/chain',headers=OP).json()
    check('受理序号早于后续编辑序号',acc['seq']<chain2['head_seq'],f"{acc['seq']} vs {chain2['head_seq']}")
    return report_id

def test_credential_pin_and_offline_verify(report_id):
    print('\n[3] 凭证固定时点 + 离线核验（篡改/乱序/删尾）')
    # 报告受理凭证
    r=client.get(f'/reports/{report_id}/credential',headers=OP)
    check('受理凭证可下载',r.status_code==200,r.text)
    bundle=r.json()
    pinned_seq=bundle['manifest']['pinned_seq']
    check('凭证固定在受理时点',pinned_seq==bundle['manifest']['records'][-1]['seq'])
    result=offline_verify(copy.deepcopy(bundle))
    check('离线核验通过且签名有效',result['valid'] and result['signature_verified'],str(result))
    # 全链凭证（当前链首）
    r=client.get('/forensics/credential',headers=ADMIN)
    check('全链凭证可下载',r.status_code==200,r.text)
    full=r.json();head_seq=full['manifest']['pinned_seq']
    check('离线核验全链凭证通过',offline_verify(copy.deepcopy(full))['valid'])
    # 后续正常修改不使旧凭证失效
    client.post('/dependencies',headers=OP,
                json={'relation_id':REL_ID,'lhs':['委托号'],'rhs':['方法'],'note':'凭证之后的新修改'})
    check('后续修改后旧受理凭证仍有效',offline_verify(copy.deepcopy(bundle))['valid'])
    r=client.get('/forensics/chain',headers=OP).json()
    check('链首已推进超过凭证时点',r['head_seq']>head_seq,f"{r['head_seq']}>{head_seq}")
    # --- 篡改内容 ---
    tampered=copy.deepcopy(bundle)
    tampered['manifest']['records'][0]['after_image']['note']='被篡改的备注'
    res=offline_verify(tampered)
    check('内容篡改被检出',(not res['valid']) and res['break_seq']==1,str(res))
    # 篡改后重算 record_hash 伪装：签名必须失效
    forged=copy.deepcopy(bundle)
    ev=forged['manifest']['records'][0]
    ev['after_image']['note']='伪装篡改'
    from scripts.verify_credential import record_hash as off_hash
    ev['record_hash']=off_hash(ev)
    res=offline_verify(forged)
    check('哈希伪装被签名识破',not res['valid'] and not res['signature_verified'],str(res))
    # --- 乱序：交换两条记录位置 ---
    reordered=copy.deepcopy(full)
    recs=reordered['manifest']['records']
    if len(recs)>=3:
        recs[0],recs[1]=recs[1],recs[0]
        res=offline_verify(reordered)
        check('乱序被检出并定位',not res['valid'] and res['break_seq'] is not None,str(res))
    # --- 删尾：移除最后一条且不更新固定时点 ---
    truncated=copy.deepcopy(full)
    truncated['manifest']['records'].pop()
    res=offline_verify(truncated)
    check('删尾（固定时点不一致）被检出',not res['valid'] and any('固定时点' in e for e in res['errors']),str(res))
    # --- 删尾并伪装固定时点：链尾 prev_hash 链接断开/签名失效 ---
    trunc2=copy.deepcopy(full)
    last=trunc2['manifest']['records'].pop()
    trunc2['manifest']['pinned_seq']=trunc2['manifest']['records'][-1]['seq']
    trunc2['manifest']['pinned_hash']=trunc2['manifest']['records'][-1]['record_hash']
    res=offline_verify(trunc2)
    check('删尾伪装被签名识破',not res['valid'] and not res['signature_verified'],str(res))
    # 历史审计记录标记无法追溯
    chain=client.get('/forensics/chain',headers=ADMIN).json()
    check('历史审计记录被保留并返回',any('历史Excel迁移' in x['action'] for x in chain['legacy_audit_logs']))
    return full

def test_page_status_transitions(full):
    print('\n[4] 页面状态：待核验 → 可信 → 损坏，并定位断裂处')
    # 待核验：空链
    reset_schema()
    with TestSession() as db:
        db.add(User(email='operator@nanlu.test',password=password_hash('Demo2026!'),role='operator'))
        db.commit()
    r=client.get('/forensics/chain',headers=login('operator'))
    check('空链状态为待核验',r.json()['state']=='pending',r.json()['state'])
    check('待核验无断裂序号',r.json()['break_seq'] is None)
    # 可信
    rel=client.post('/relations',headers=login('operator'),
                    json={'code':'NL-T-2','title':'状态迁移','attributes':['A','B'],'note':''}).json()
    r=client.get('/forensics/chain',headers=login('operator'))
    check('产生记录后状态可信',r.json()['state']=='trusted',r.json()['state'])
    # 损坏：直接改库制造篡改（绕过服务层）
    with TestSession() as db:
        ev=db.query(ChangeEvidence).order_by(ChangeEvidence.seq).first()
        ev.after_image={**ev.after_image,'note':'库内直接篡改'}
        db.commit()
    r=client.get('/forensics/chain',headers=login('operator')).json()
    check('篡改后状态损坏',r['state']=='damaged',r['state'])
    check('断裂定位到 seq=1',r['break_seq']==1,str(r['break_seq']))
    check('核验在断裂处停止',len(r['checks'])==1)
    # 乱序损坏定位
    reset_schema()
    with TestSession() as db:
        db.add(User(email='operator@nanlu.test',password=password_hash('Demo2026!'),role='operator'));db.commit()
    h=login('operator')
    r1=client.post('/relations',headers=h,json={'code':'X1','title':'乱序用例甲','attributes':['A'],'note':''})
    r2=client.post('/relations',headers=h,json={'code':'X2','title':'乱序用例乙','attributes':['B'],'note':''})
    assert r1.status_code==201 and r2.status_code==201,(r1.text,r2.text)
    with TestSession() as db:
        ev2=db.query(ChangeEvidence).filter_by(seq=2).one()
        ev2.prev_hash='f'*64  # 破坏链接
        db.commit()
    r=client.get('/forensics/chain',headers=h).json()
    check('链接损坏定位 seq=2',r['state']=='damaged' and r['break_seq']==2,str(r))

def test_report_acceptance_rollback():
    print('\n[5] 报告受理取证失败 → 报告与取证整体回滚')
    reset_schema()
    ensure_users()
    h=login('operator')
    with TestSession() as db:
        rel=Relation(code='NL-RB-1',title='回滚用草案',attributes=['A','B'],note='');db.add(rel);db.commit()
        rid=rel.id
    orig=forensics.append_evidence
    forensics.append_evidence=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('取证故障'))
    try:
        r=client.post('/reports',headers=h,json={'name':'应回滚的受理','relation_id':rid})
        check('受理失败返回 500',r.status_code==500,str(r.status_code))
    finally:
        forensics.append_evidence=orig
    with TestSession() as db:
        check('报告记录未残留',db.query(entities.Report).count()==0)
        check('取证记录未残留',db.query(ChangeEvidence).count()==0)
        check('ChainMeta 未推进',db.get(ChainMeta,1) is None or db.get(ChainMeta,1).head_seq==0)
    # 恢复后可正常受理
    r=client.post('/reports',headers=h,json={'name':'恢复后的受理','relation_id':rid})
    check('恢复后受理成功',r.status_code==201,r.text)
    check('恢复后链可信',client.get('/forensics/chain',headers=h).json()['state']=='trusted')

if __name__=='__main__':
    ensure_users()
    OP=login('operator');ADMIN=login('admin');VIEWER=login('viewer')
    test_crud_evidence_and_rollback()
    rid=test_concurrent_edits_and_acceptance()
    full=test_credential_pin_and_offline_verify(rid)
    test_page_status_transitions(full)
    test_report_acceptance_rollback()
    print(f'\n==== 结果：{PASS} 通过 / {FAIL} 失败 ====')
    sys.exit(1 if FAIL else 0)
