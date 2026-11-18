#!/usr/bin/env python3
"""实验册变更凭证离线核验工具。

用法：
    python -m scripts.verify_credential <凭证文件.json> [--public-key pub.pem]

不依赖数据库或后端服务：重算每条取证记录的 SHA256、核对 prev_hash 链接与序号连续性，
可检出内容篡改、乱序与删尾；提供 Ed25519 公钥时进一步验签，确认凭证来源。
凭证内自带 public_key_pem，默认使用凭证内嵌公钥（如不信任可通过 --public-key 覆盖）。
"""
import sys,json,hashlib,hmac,argparse

GENESIS_HASH='0'*64

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))

def record_hash(ev):
    payload={k:ev[k] for k in ('seq','kind','entity_type','entity_id','before_image',
                               'after_image','source_anchors','actor','occurred_at','prev_hash')}
    return hashlib.sha256(canonical(payload).encode('utf-8')).hexdigest()

def verify(bundle,pem_text=None):
    errors=[];signature_verified=False;break_seq=None
    try:
        manifest=bundle['manifest'];records=manifest['records']
    except (KeyError,TypeError) as e:
        return {'valid':False,'errors':[f'凭证结构非法：{e}'],'records_checked':0}
    pem=pem_text or bundle.get('public_key_pem')
    if pem:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives import serialization
            pub=serialization.load_pem_public_key(pem.encode('ascii'))
            pub.verify(bytes.fromhex(bundle['signature']),canonical(manifest).encode('utf-8'))
            signature_verified=True
        except Exception as e:
            errors.append(f'签名核验失败：{e}')
    else:
        errors.append('未提供公钥，仅完成链内核验，无法证明凭证来源')
    prev=GENESIS_HASH;expected=1
    for ev in records:
        if ev['seq']!=expected:
            errors.append(f"乱序/删尾：期望 seq={expected}，实际 seq={ev['seq']}");break_seq=ev['seq'];break
        if ev['prev_hash']!=prev:
            errors.append(f"链断裂于 seq={ev['seq']}：prev_hash 不匹配（乱序或删尾）");break_seq=ev['seq'];break
        if not hmac.compare_digest(record_hash(ev),ev['record_hash']):
            errors.append(f"内容篡改于 seq={ev['seq']}：record_hash 重算不一致");break_seq=ev['seq'];break
        prev=ev['record_hash'];expected+=1
    if records and manifest.get('pinned_seq')!=records[-1]['seq']:
        errors.append('固定时点 pinned_seq 与凭证末条记录不一致')
    if records and manifest.get('pinned_hash')!=records[-1]['record_hash']:
        errors.append('固定时点 pinned_hash 与凭证末条记录不一致')
    return {'valid':not errors,'signature_verified':signature_verified,'break_seq':break_seq,
            'records_checked':len(records),'pinned_seq':manifest.get('pinned_seq'),
            'subject':manifest.get('subject'),'errors':errors}

def main():
    ap=argparse.ArgumentParser(description='实验册变更凭证离线核验')
    ap.add_argument('credential',help='下载的凭证 JSON 文件路径')
    ap.add_argument('--public-key',help='可信 Ed25519 公钥 PEM（默认使用凭证内嵌公钥）')
    args=ap.parse_args()
    with open(args.credential,encoding='utf-8') as f:bundle=json.load(f)
    pem=None
    if args.public_key:
        with open(args.public_key,encoding='utf-8') as f:pem=f.read()
    result=verify(bundle,pem)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    sys.exit(0 if result['valid'] else 1)

if __name__=='__main__':main()
