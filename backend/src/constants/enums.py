ROLES = ('admin', 'operator', 'viewer')
RUN_STATES = ('queued', 'running', 'completed', 'failed')
# 取证链核验状态：待核验（尚未做过离线/在线核验）、可信、损坏（断裂定位处）、无法追溯（断裂点之后的旧记录）
CHAIN_STATES = ('pending', 'trusted', 'damaged', 'untraceable')
# 取证动作类别：业务变更（草案/依赖写入）与报告受理（入队冻结）
EVIDENCE_KINDS = ('relation_create', 'relation_update', 'dependency_create', 'dependency_update', 'report_accept')
