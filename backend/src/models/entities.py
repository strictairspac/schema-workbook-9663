from sqlalchemy import Column,Integer,String,JSON,DateTime,ForeignKey,Text
from datetime import datetime,timezone
from src.config.database import Base
class User(Base):
    __tablename__='users'
    id=Column(Integer,primary_key=True);email=Column(String(120),unique=True,nullable=False);password=Column(String(300),nullable=False);role=Column(String(20),nullable=False)
class Relation(Base):
    __tablename__='relations'
    id=Column(Integer,primary_key=True);code=Column(String(80),unique=True,nullable=False);title=Column(String(160),nullable=False);attributes=Column(JSON,nullable=False);note=Column(String(300),default='')
    # 实体当前版本号，每次成功修改 +1；取证记录按版本保存前后镜像
    version=Column(Integer,nullable=False,default=1)
class Dependency(Base):
    __tablename__='dependencies'
    id=Column(Integer,primary_key=True);relation_id=Column(Integer,ForeignKey('relations.id'),nullable=False);lhs=Column(JSON,nullable=False);rhs=Column(JSON,nullable=False);note=Column(String(300),default='')
    version=Column(Integer,nullable=False,default=1)
class Report(Base):
    __tablename__='reports'
    id=Column(Integer,primary_key=True);name=Column(String(120),nullable=False);relation_id=Column(Integer,ForeignKey('relations.id'),nullable=False)
    status=Column(String(20),nullable=False,default='queued');input_snapshot=Column(JSON,nullable=False);result=Column(JSON,nullable=True);error=Column(Text,nullable=True)
    # 受理时点：取证链序号、所采用来源（草案/依赖版本）与受理取证哈希，下载凭证固定于此提交时点
    accept_seq=Column(Integer,nullable=True);source_anchors=Column(JSON,nullable=True);accept_evidence_hash=Column(String(64),nullable=True)
    created_at=Column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class Audit(Base):
    __tablename__='audit_logs'
    id=Column(Integer,primary_key=True);actor=Column(String(120),nullable=False);action=Column(String(160),nullable=False);created_at=Column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class ChangeEvidence(Base):
    """变更取证：只追加（append-only）的哈希链，覆盖每次成功的业务修改与报告受理。"""
    __tablename__='change_evidences'
    id=Column(Integer,primary_key=True)
    # 全局单调序号，串行化所有写入，供并发编辑/受理核对先后
    seq=Column(Integer,unique=True,nullable=False,index=True)
    kind=Column(String(40),nullable=False)
    entity_type=Column(String(40),nullable=False);entity_id=Column(Integer,nullable=False)
    # 变更前后完整内容（创建时 before 为 null，报告受理 before/after 为同一冻结快照）
    before_image=Column(JSON,nullable=True);after_image=Column(JSON,nullable=False)
    # 报告受理采用的来源：{relation_version, dependency_versions:[...], evidence_hashes:[...]}
    source_anchors=Column(JSON,nullable=True)
    actor=Column(String(120),nullable=False)
    # 固定格式 ISO8601 字符串（微秒+UTC），保证离线重算哈希与库内记录逐字节一致
    occurred_at=Column(String(40),nullable=False)
    prev_hash=Column(String(64),nullable=False);record_hash=Column(String(64),nullable=False,index=True)
    created_at=Column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class ChainMeta(Base):
    """单行元数据表：行锁串行化序号分配，保证并发提交取得连续且可核对的先后次序。"""
    __tablename__='chain_meta'
    id=Column(Integer,primary_key=True)
    head_seq=Column(Integer,nullable=False,default=0);head_hash=Column(String(64),nullable=False,default='')
