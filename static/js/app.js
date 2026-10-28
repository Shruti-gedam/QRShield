'use strict';

const $ = id => document.getElementById(id);
const sess = { total:0, safe:0, sus:0, high:0, crit:0, scores:[] };
let hist = [], showAll = false, activeTab = 'tab-upload', selFile = null;

/* NAVIGATION */
document.querySelectorAll('.nav-item').forEach(n => {
  n.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
    n.classList.add('active');
    const v = n.dataset.view;
    $('view-' + v).classList.add('active');
    if (v === 'stats')   renderStats();
    if (v === 'history') renderHist();
  });
});

/* TABS */
document.querySelectorAll('.tab-btn').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(x => { x.classList.remove('active'); x.setAttribute('aria-selected','false'); });
    document.querySelectorAll('.tab-pane').forEach(x => x.classList.add('hidden'));
    b.classList.add('active');
    b.setAttribute('aria-selected','true');
    activeTab = b.dataset.tab;
    $(activeTab).classList.remove('hidden');
    updateBtn();
  });
});

function updateBtn() {
  const ok = (activeTab==='tab-upload' && selFile!==null) ||
             (activeTab==='tab-payload' && $('payload-inp').value.trim().length>0);
  $('scan-btn').disabled = !ok;
}
$('payload-inp').addEventListener('input', updateBtn);

/* DRAG & DROP */
const dz = $('drop-zone');
dz.addEventListener('click', () => $('file-input').click());
dz.addEventListener('keydown', e => { if(e.key==='Enter'||e.key===' ') $('file-input').click(); });
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag-over'); const f=e.dataTransfer?.files?.[0]; if(f) pick(f); });
$('file-input').addEventListener('change', () => { if($('file-input').files?.[0]) pick($('file-input').files[0]); });

function pick(f) {
  const ok = ['image/jpeg','image/jpg','image/png','image/webp','image/bmp'];
  if(!ok.includes(f.type)) return err('Unsupported file type. Use JPEG, PNG, or WebP.');
  if(f.size > 10*1024*1024) return err('File too large. Max 10 MB.');
  clearErr(); selFile = f;
  const r = new FileReader();
  r.onload = e => { $('prev-img').src=e.target.result; $('prev-img').classList.remove('hidden'); $('drop-lbl').classList.add('hidden'); };
  r.readAsDataURL(f);
  updateBtn();
}

/* CONTEXT */
function ctx() {
  const c = {};
  if($('ctx-co').value.trim()) c.country_code     = $('ctx-co').value.trim().toUpperCase();
  if($('ctx-mc').value.trim()) c.merchant_country = $('ctx-mc').value.trim().toUpperCase();
  if($('ctx-dv').value)        c.device_type      = $('ctx-dv').value;
  if($('ctx-wf').value!=='')   c.is_wifi          = $('ctx-wf').value==='true';
  if($('ctx-ss').value.trim()) c.wifi_ssid        = $('ctx-ss').value.trim();
  if($('ctx-am').value)        c.declared_amount  = parseFloat($('ctx-am').value);
  c.scan_timestamp = new Date().toISOString();
  return c;
}

/* SCAN */
$('scan-btn').addEventListener('click', runScan);

async function runScan() {
  clearErr(); loading(true);
  try {
    const data = activeTab==='tab-upload' ? await doUpload() : await doPayload();
    render(data); track(data); addHist(data);
  } catch(e) {
    err(e.message || 'Network error. Is the server running?');
    idle();
  } finally { loading(false); }
}

async function doUpload() {
  const fd = new FormData();
  fd.append('file', selFile);
  fd.append('context_json', JSON.stringify(ctx()));
  const m = $('msg-inp').value.trim();
  if(m) fd.append('message', m);
  const r = await fetch('/api/scan/upload', {method:'POST', body:fd});
  if(!r.ok) { const e=await r.json().catch(()=>{}); throw new Error(e?.detail||`Error ${r.status}`); }
  return r.json();
}

async function doPayload() {
  const p = $('payload-inp').value.trim();
  if(!p) throw new Error('Please enter a QR payload string.');
  const m = $('msg-inp').value.trim();
  const r = await fetch('/api/scan/payload', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({payload:p, context:ctx(), ...(m?{message:m}:{})})
  });
  if(!r.ok) { const e=await r.json().catch(()=>{}); throw new Error(e?.detail||`Error ${r.status}`); }
  return r.json();
}

/* STATE HELPERS */
function loading(on) {
  $('scan-btn').disabled = on;
  $('scan-txt').textContent = on ? 'Analyzing…' : '🔍 Analyze QR';
  $('scan-spin').classList.toggle('hidden', !on);
  if(on) { $('r-idle').classList.add('hidden'); $('r-content').classList.add('hidden'); $('r-load').classList.remove('hidden'); }
}
function idle() { $('r-load').classList.add('hidden'); $('r-content').classList.add('hidden'); $('r-idle').classList.remove('hidden'); }
function err(m) { $('inp-err').textContent=m; $('inp-err').classList.remove('hidden'); }
function clearErr() { $('inp-err').textContent=''; $('inp-err').classList.add('hidden'); }

/* RENDER */
function render(d) {
  $('r-load').classList.add('hidden');
  $('r-idle').classList.add('hidden');
  $('r-content').classList.remove('hidden');
  renderVerdict(d);
  renderDec(d.deception);
  renderSS(d.sub_scores);
  $('exp-txt').textContent = d.explanation || '—';
  renderRecs(d.recommendations);
  renderFindings(d.top_findings, d.all_findings);
  renderPayload(d.payload);
  renderRedir(d.url_analysis);
  $('raw-json').textContent = JSON.stringify(d, null, 2);
}

function renderVerdict(d) {
  const v = d.verdict;
  $('vrd-banner').className = 'vrd-banner vrd-' + v;
  $('vrd-icon').textContent  = d.verdict_icon;
  $('vrd-label').textContent = v.replace('_',' ');
  $('vrd-label').style.color = d.verdict_color;
  $('vrd-score').textContent = 'Risk score: ' + d.score + ' / 100';
  const C = 238.8, off = C - (d.score/100)*C;
  const gf = $('g-fill');
  gf.style.strokeDashoffset = off;
  gf.setAttribute('class', 'g-fill ring-' + ({SAFE:'safe',SUSPICIOUS:'suspicious',HIGH_RISK:'high',CRITICAL:'critical'}[v]||'safe'));
  $('g-num').textContent = d.score;
  $('g-num').style.color = d.verdict_color;
}

function renderDec(dec) {
  const p = $('dec-panel');
  if(!dec) { p.classList.add('hidden'); return; }
  if(!dec.is_deceptive) {
    if(dec.message_intent) {
      p.className='dec-safe'; p.innerHTML='<span>✅</span><span>Message intent matches QR action — no deception detected.</span>';
      p.classList.remove('hidden');
    } else p.classList.add('hidden');
    return;
  }
  p.className='dec-panel'; p.classList.remove('hidden');
  const mi = dec.message_intent;
  $('d-msg-int').textContent = mi ? 'Intent: '+mi.intent : 'Unknown';
  $('d-msg-amt').textContent = mi?.primary_amount!=null ? 'Amount: Rs.'+fmtN(mi.primary_amount) : '';
  $('d-msg-raw').textContent = mi ? '"'+mi.raw_message.substring(0,100)+(mi.raw_message.length>100?'...':'')+'"' : '';
  $('d-qr-act').textContent  = 'Action: '+dec.qr_action;
  $('d-qr-amt').textContent  = dec.qr_amount!=null ? 'Amount: Rs.'+fmtN(dec.qr_amount) : '';
  $('d-qr-vpa').textContent  = dec.qr_vpa ? 'Recipient: '+dec.qr_vpa : '';
  $('d-types').innerHTML = (dec.deception_types||[]).map(t=>`<span class="dec-badge">${t.replace(/_/g,' ')}</span>`).join('');
  $('d-summary').textContent = dec.summary||'';
}

function renderSS(sub) {
  const g = $('ss-grid'); g.innerHTML='';
  [['payload','Payload'],['url','URL'],['context','Context'],['decode','Decode'],['deception','Deception']].forEach(([k,l])=>{
    const v = sub?.[k]??0;
    const row = document.createElement('div'); row.className='ss-row';
    row.innerHTML=`<span class="ss-lbl">${l}</span><div class="ss-wrap"><div class="ss-bar" style="width:0"></div></div><span class="ss-val">${v}</span>`;
    g.appendChild(row);
    requestAnimationFrame(()=>requestAnimationFrame(()=>{
      const b=row.querySelector('.ss-bar');
      b.style.width=v+'%';
      b.style.background=v<30?'var(--safe)':v<60?'var(--warn)':v<80?'var(--high)':'var(--crit)';
    }));
  });
}

function renderRecs(recs) {
  const s=$('recs-sec');
  if(!recs||!recs.length){s.classList.add('hidden');return;}
  s.classList.remove('hidden');
  $('recs-list').innerHTML=recs.map(r=>`<li>${esc(r)}</li>`).join('');
}

function renderFindings(top, all) {
  $('f-top').innerHTML = top.map(fc).join('') || '<p style="color:var(--muted);font-size:.82rem;padding:6px">No significant findings.</p>';
  $('f-all').innerHTML = all.map(fc).join('');
  showAll=false; $('f-all').classList.add('hidden'); $('f-top').classList.remove('hidden');
  $('toggle-f').textContent = 'Show all ('+all.length+')';
}
$('toggle-f').addEventListener('click',()=>{
  showAll=!showAll;
  $('f-all').classList.toggle('hidden',!showAll);
  $('f-top').classList.toggle('hidden',showAll);
  $('toggle-f').textContent=showAll?'Show top only':'Show all ('+$('f-all').querySelectorAll('.fc').length+')';
});
function fc(f) {
  const s=(f.severity||'info').toLowerCase();
  return `<div class="fc"><span class="sb sev-${s}">${s}</span><div><div class="f-rule">${esc(f.rule)}</div><div class="f-desc">${esc(f.description)}</div>${f.evidence?`<div class="f-ev">${esc(f.evidence)}</div>`:''}</div></div>`;
}

function renderPayload(p) {
  if(!p){$('pay-det').innerHTML='';return;}
  const items=[{k:'Format',v:p.format||'—'},{k:'Status',v:p.status||'—'},...Object.entries(p.fields||{}).filter(([k])=>k!=='all_params').map(([k,v])=>({k:fmtK(k),v:String(v||'—')}))];
  if(p.raw) items.push({k:'Raw',v:p.raw});
  $('pay-det').innerHTML=items.map(({k,v})=>`<div class="det-item"><div class="det-k">${esc(k)}</div><div class="det-v">${esc(v)}</div></div>`).join('');
}

function renderRedir(ua) {
  const s=$('redir-sec');
  if(!ua?.redirect_chain||ua.redirect_chain.length<2){s.classList.add('hidden');return;}
  s.classList.remove('hidden');
  $('redir-ol').innerHTML=ua.redirect_chain.map(u=>`<li>${esc(u)}</li>`).join('');
}

/* STATS */
function track(d) {
  sess.total++; sess.scores.push(d.score);
  const v=d.verdict;
  if(v==='SAFE')sess.safe++;else if(v==='SUSPICIOUS')sess.sus++;else if(v==='HIGH_RISK')sess.high++;else sess.crit++;
  $('s-total').textContent=sess.total; $('s-safe').textContent=sess.safe;
  $('s-sus').textContent=sess.sus; $('s-high').textContent=sess.high; $('s-crit').textContent=sess.crit;
}
function renderStats() {
  $('ov-safe').textContent=sess.safe; $('ov-sus').textContent=sess.sus;
  $('ov-high').textContent=sess.high; $('ov-crit').textContent=sess.crit;
  const mx=Math.max(sess.safe,sess.sus,sess.high,sess.crit,1);
  $('bar-safe').style.width=(sess.safe/mx*100)+'%'; $('bar-sus').style.width=(sess.sus/mx*100)+'%';
  $('bar-high').style.width=(sess.high/mx*100)+'%'; $('bar-crit').style.width=(sess.crit/mx*100)+'%';
  const avg=sess.scores.length?Math.round(sess.scores.reduce((a,b)=>a+b,0)/sess.scores.length):0;
  $('avg-fill').style.width=avg+'%'; $('avg-txt').textContent=avg+' / 100';
}

/* HISTORY */
function addHist(d) {
  hist.unshift({ico:d.verdict_icon,verdict:d.verdict,score:d.score,color:d.verdict_color,pay:d.payload?.raw||d.payload?.format||'—',time:new Date().toLocaleTimeString()});
}
function renderHist() {
  const el=$('hist-list');
  if(!hist.length){el.innerHTML='<p class="hist-empty">No scans yet.</p>';return;}
  el.innerHTML=hist.map(h=>`
    <div class="hist-item">
      <span class="hist-ico">${h.ico}</span>
      <div class="hist-inf"><div class="hist-pay">${esc(h.pay.substring(0,90))}${h.pay.length>90?'…':''}</div><div class="hist-time">${h.time}</div></div>
      <span class="hist-sc" style="color:${h.color}">${h.score}</span>
      <span class="hist-vrd" style="background:${h.color}22;color:${h.color}">${h.verdict.replace('_',' ')}</span>
    </div>`).join('');
}
$('clr-hist').addEventListener('click',()=>{hist=[];renderHist();});

/* HEALTH */
async function health() {
  const dot=$('hdot'), txt=$('htext');
  try {
    const r=await fetch('/api/health'); const d=await r.json();
    if(d.status==='healthy'){dot.classList.add('ok');txt.textContent='System healthy';}
    else{dot.classList.add('deg');txt.textContent='Degraded';}
  } catch{dot.classList.add('err');txt.textContent='Offline';}
}

/* UTILS */
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function fmtN(n){return Number(n).toLocaleString('en-IN',{minimumFractionDigits:2});}
function fmtK(k){return k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());}

health();
