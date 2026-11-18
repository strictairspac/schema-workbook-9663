import os
DATABASE_URL=os.getenv('DATABASE_URL','mysql+pymysql://schemaworkbook:schemaworkbook_demo_pw@localhost:17743/schemaworkbook')
REDIS_URL=os.getenv('REDIS_URL','redis://redis:6379/0')
JWT_SECRET=os.getenv('JWT_SECRET','local-schema-workbook-change-before-public-use')
# 取证凭证 Ed25519 签名密钥的确定性派生秘密；生产环境必须通过环境变量覆盖
EVIDENCE_SECRET=os.getenv('EVIDENCE_SECRET','local-evidence-secret-change-before-public-use')
