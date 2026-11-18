import {esc,date} from '../utils/html.js';
import {CHAIN_STATES,EVIDENCE_KINDS} from '../constants/enums.js';
import {table} from '../components/common/table.js';

const stateBadge=state=>{
  const cls=state==='trusted'?'badge completed':state==='damaged'?'badge failed':state==='untraceable'?'badge failed':'badge queued';
  return `<span class="${cls}">${esc(CHAIN_STATES[state]||state)}</span>`;
};
const kindLabel=k=>EVIDENCE_KINDS[k]||k;

export function forensicsPage(chain){
  if(!chain)return '<div class="empty">取证链加载中。</div>';
  const state=chain.state;
  const verdict=state==='trusted'
    ?`<div class="verdict"><div class="verdict-icon">✓</div><div><span class="eyebrow">CHAIN VERIFIED</span><h2>取证链可信</h2><p>共 ${chain.length} 条取证记录，链首 seq=${chain.head_seq}，全部哈希链接核验通过。</p></div></div>`
    :state==='damaged'
    ?`<div class="verdict verdict-bad"><div class="verdict-icon">!</div><div><span class="eyebrow">CHAIN BROKEN</span><h2>取证链损坏</h2><p>断裂定位：seq=${esc(chain.break_seq)}。该序号处记录存在篡改、乱序或删尾，其后记录不再具有追溯效力。</p></div></div>`
    :`<div class="verdict verdict-pending"><div class="verdict-icon">…</div><div><span class="eyebrow">PENDING VERIFICATION</span><h2>待核验</h2><p>尚无取证记录或尚未完成核验；产生一次成功修改后即可下载凭证并离线核验。</p></div></div>`;
  const rows=chain.records.map(ev=>[
    `<strong>#${ev.seq}</strong><small>${date(ev.occurred_at)}</small>`,
    esc(ev.actor),
    kindLabel(ev.kind),
    `${esc(ev.entity_type)} #${ev.entity_id}`,
    `<code class="hash">${esc(ev.record_hash.slice(0,16))}…</code>`,
    `<button class="small show-images" data-seq="${ev.seq}">前后内容</button>`,
  ]);
  const legacy=chain.legacy_audit_logs||[];
  return `<div class="forensics">
    <div class="evidence-top">
      <div><span class="eyebrow">CHANGE FORENSICS / 变更取证</span><h2>取证链状态 ${stateBadge(state)}</h2><p>每次成功修改的前后内容、操作者与报告来源均入哈希链；序号全局连续，可核对并发先后。</p></div>
      <div class="btn-row">
        <button id="verify-chain">重新核验</button>
        <button class="primary" id="download-credential" ${state==='pending'?'disabled':''}>下载全链凭证 ↓</button>
      </div>
    </div>
    ${verdict}
    <div class="section-top"><h2>取证记录（append-only）</h2><span>${chain.length} 条 / HEAD ${esc(chain.head_hash.slice(0,16))}…</span></div>
    ${chain.length?table(['序号 / 时间','操作者','动作','对象','记录哈希','镜像'],rows):'<div class="notice">还没有取证记录。</div>'}
    <div class="image-drawer" id="image-drawer" hidden></div>
    <div class="section-top"><h2>历史操作记录</h2><span>${stateBadge('untraceable')} 无前后镜像与哈希链接</span></div>
    ${legacy.length?table(['时间','操作人','动作 / 追溯状态'],legacy.map(x=>[date(x.created_at),esc(x.actor),`${esc(x.action)} <small>（${CHAIN_STATES.untraceable}）</small>`])):'<div class="notice">无历史记录。</div>'}
    <div class="evidence-notes"><section><h3>离线核验</h3><p>凭证内含 Ed25519 公钥与全量记录，使用 <code>scripts/verify_credential.py</code> 可离线检出内容篡改、乱序与删尾。凭证固定在下载时的已提交时点，后续正常修改不会使旧凭证失效。</p></section><section><h3>验签公钥</h3><code class="pubkey">${esc(chain.public_key_pem)}</code></section></div>
  </div>`;
}

export function bindImageDrawer(chain){
  const drawer=document.querySelector('#image-drawer');
  document.querySelectorAll('.show-images').forEach(btn=>btn.onclick=()=>{
    const ev=chain.records.find(x=>x.seq===Number(btn.dataset.seq));
    if(!ev)return;
    drawer.hidden=false;
    drawer.innerHTML=`<div class="section-top"><h2>#${ev.seq} ${esc(kindLabel(ev.kind))} · 前后内容</h2><button class="small" id="close-drawer">收起</button></div>
      <div class="split"><section><h3>变更前</h3><pre>${ev.before_image?esc(JSON.stringify(ev.before_image,null,2)):'（创建动作，无前值）'}</pre></section>
      <section><h3>变更后</h3><pre>${esc(JSON.stringify(ev.after_image,null,2))}</pre></section></div>
      ${ev.source_anchors?`<h3>报告采用来源</h3><pre>${esc(JSON.stringify(ev.source_anchors,null,2))}</pre>`:''}`;
    drawer.scrollIntoView({behavior:'smooth',block:'center'});
    document.querySelector('#close-drawer').onclick=()=>{drawer.hidden=true;};
  });
}
