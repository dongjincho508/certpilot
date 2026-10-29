/** CertPilot 관리 화면 (Bootstrap 5 + Bootswatch). 모든 값은 textContent 로만 삽입한다(XSS 방지). */
'use strict';

const $ = (id) => document.getElementById(id);
const STATUS = {
  OK:         { label: '정상',           cls: 'text-bg-success',                       icon: 'bi-check-circle-fill' },
  WARN:       { label: '만료 임박',      cls: 'text-bg-warning',                       icon: 'bi-exclamation-triangle-fill' },
  EXPIRED:    { label: '만료',           cls: 'text-bg-danger',                        icon: 'bi-x-octagon-fill' },
  CHAIN_RISK: { label: '체인 위험',      cls: 'text-bg-danger-subtle text-danger-emphasis border border-danger-subtle', icon: 'bi-link-45deg' },
  NOT_YET:    { label: '유효 전',        cls: 'text-bg-info',                          icon: 'bi-hourglass-split' },
  FETCH_FAIL: { label: '조회 실패',      cls: 'text-bg-secondary',                     icon: 'bi-plug-fill' },
  NOT_FOUND:  { label: '인증서 미발견',  cls: 'text-bg-secondary-subtle text-secondary-emphasis border', icon: 'bi-search' },
  UNKNOWN:    { label: '확인 필요',      cls: 'text-bg-primary-subtle text-primary-emphasis border border-primary-subtle', icon: 'bi-question-circle-fill' },
};
const ROLE = { leaf: '리프', intermediate: '중간 CA', root: '루트' };
const STAT_CARDS = [
  { key: 'OK', title: '정상', icon: 'bi-check-circle', tone: 'success', match: ['OK'] },
  { key: 'WARN', title: '만료 임박', icon: 'bi-exclamation-triangle', tone: 'warning', match: ['WARN'] },
  { key: 'RISK', title: '만료 · 체인 위험', icon: 'bi-x-octagon', tone: 'danger', match: ['EXPIRED', 'CHAIN_RISK', 'NOT_YET'] },
  { key: 'OTHER', title: '실패 · 미발견 · 확인 필요', icon: 'bi-question-circle', tone: 'secondary', match: ['FETCH_FAIL', 'NOT_FOUND', 'UNKNOWN', null] },
];

let me = null, allServers = [], cardFilter = null, detailServerId = null;
let detailOffcanvas, serverModal, pwModal, mfaModal;

async function api(path, method = 'GET', body = null) {
  const opt = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
  if (body !== null) opt.body = JSON.stringify(body);
  const res = await fetch(path, opt);
  if (res.status === 401 && !path.startsWith('/auth/')) { showLogin(); throw new Error('로그인이 필요합니다.'); }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const rid = res.headers.get('X-Request-Id');
    const err = new Error(((data && data.error && data.error.message) || `오류 ${res.status}`) + (rid && res.status >= 500 ? ` [요청 ID ${rid}]` : ''));
    err.code = data && data.error && data.error.code; throw err;
  }
  return data;
}

// ---------------------------------------------------------------- DOM 헬퍼
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function icon(name) { return el('i', null, `bi ${name}`); }
function badge(status) {
  const s = STATUS[status];
  const b = el('span', null, `badge rounded-pill ${s ? s.cls : 'text-bg-light border text-body-secondary'}`);
  b.append(icon(s ? s.icon : 'bi-dash-circle'), document.createTextNode(s ? s.label : '미조회'));
  return b;
}
function cell(content, cls) {
  const td = document.createElement('td');
  if (cls) td.className = cls;
  td.append(content instanceof Node ? content : (content ?? '-'));
  return td;
}
function btn(text, cls, fn, iconName) {
  const b = el('button', null, `btn btn-sm ${cls}`);
  b.type = 'button';
  if (iconName) b.append(icon(iconName));
  if (text) b.append(document.createTextNode((iconName ? ' ' : '') + text));
  b.addEventListener('click', (e) => { e.stopPropagation(); fn(e); });
  return b;
}
function toast(msg, kind = 'success') {
  const t = el('div', null, `toast align-items-center text-bg-${kind} border-0`);
  t.role = 'status';
  const row = el('div', null, 'd-flex');
  row.append(el('div', msg, 'toast-body'));
  const x = el('button', null, 'btn-close btn-close-white me-2 m-auto');
  x.type = 'button'; x.setAttribute('data-bs-dismiss', 'toast'); x.setAttribute('aria-label', '닫기');
  row.append(x); t.append(row); $('toasts').append(t);
  const inst = new bootstrap.Toast(t, { delay: 5000 }); inst.show();
  t.addEventListener('hidden.bs.toast', () => t.remove());
}
async function guarded(fn) { try { await fn(); } catch (e) { toast(e.message, 'danger'); } }
async function busy(button, fn) {
  button.disabled = true;
  const spin = el('span', null, 'spinner-border spinner-border-sm me-1'); button.prepend(spin);
  try { await fn(); } finally { spin.remove(); button.disabled = false; }
}

// ---------------------------------------------------------------- 화면 전환
function showLogin() {
  me = null; $('app-view').hidden = true; $('login-view').hidden = false; $('login-pass').value = '';
  $('login-code-wrap').hidden = true; $('login-code').value = '';
}
function showView(name) {
  ['dashboard', 'audit', 'users', 'debug', 'cd'].forEach((v) => { $(`view-${v}`).hidden = v !== name; });
  document.querySelectorAll('#main-tabs .nav-link').forEach((a) => a.classList.toggle('active', a.dataset.view === name));
  if (name === 'dashboard') guarded(loadServers);
  if (name === 'audit') guarded(loadAudit);
  if (name === 'users') guarded(loadUsers);
  if (name === 'debug') guarded(loadDebug);
  if (name === 'cd') guarded(loadCd);
}
function enter(user) {
  me = user; $('login-view').hidden = true; $('app-view').hidden = false;
  $('whoami').textContent = `${user.username} · ${user.role === 'admin' ? '관리자' : '운영자'}`;
  document.querySelectorAll('.admin-only').forEach((e) => { e.hidden = user.role !== 'admin'; });
  showView('dashboard');
  api('/auth/mfa').then((m) => { if (m.required && !m.enabled) { toast('보안 정책상 2단계 인증을 먼저 등록해야 합니다.', 'warning'); openMfa(); } }).catch(() => {});
}

// ---------------------------------------------------------------- 현황
function renderStatCards() {
  const wrap = $('stat-cards'); wrap.replaceChildren();
  STAT_CARDS.forEach((c) => {
    const count = allServers.filter((s) => c.match.includes(s.status)).length;
    const col = el('div', null, 'col-6 col-lg-3');
    const card = el('div', null, `card stat-card h-100 shadow-sm${cardFilter === c.key ? ' active' : ''}`);
    card.tabIndex = 0; card.setAttribute('role', 'button'); card.setAttribute('aria-pressed', String(cardFilter === c.key));
    const body = el('div', null, 'card-body d-flex align-items-center gap-3');
    const ic = el('div', null, `stat-icon bg-${c.tone}-subtle text-${c.tone}-emphasis`); ic.append(icon(c.icon));
    const txt = el('div'); txt.append(el('div', String(count), 'stat-value'), el('div', c.title, 'small text-body-secondary'));
    body.append(ic, txt); card.append(body); col.append(card); wrap.append(col);
    const toggle = () => { cardFilter = cardFilter === c.key ? null : c.key; renderStatCards(); renderTable(); };
    card.addEventListener('click', toggle);
    card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
  });
}
function filteredServers() {
  const text = $('filter-text').value.trim().toLowerCase();
  const st = $('filter-status').value, grp = $('filter-group').value;
  const card = STAT_CARDS.find((c) => c.key === cardFilter);
  return allServers.filter((s) =>
    (!text || s.name.toLowerCase().includes(text) || s.hostname.toLowerCase().includes(text)) &&
    (!st || s.status === st) && (!grp || s.group === grp) && (!card || card.match.includes(s.status)));
}
function renderTable() {
  const tb = $('servers-body'); tb.replaceChildren();
  const rows = filteredServers();
  if (!rows.length) {
    const tr = document.createElement('tr'); const td = el('td', null, 'text-center text-body-secondary py-5'); td.colSpan = 6;
    td.append(icon('bi-inbox'), el('div', allServers.length ? '조건에 맞는 서버가 없습니다.' : '등록된 서버가 없습니다.', 'mt-2'));
    tr.append(td); tb.append(tr); return;
  }
  rows.forEach((s) => {
    const tr = document.createElement('tr');
    tr.tabIndex = 0; tr.addEventListener('click', () => guarded(() => openDetail(s.id)));
    tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') guarded(() => openDetail(s.id)); });
    const name = el('div'); name.append(el('div', s.name, 'fw-semibold'), el('div', `${s.hostname}:${s.port}`, 'small text-body-secondary'));
    const st = el('div'); st.append(badge(s.status));
    if (s.hostkey_blocked) st.append(el('span', ' 호스트 키 변경', 'badge text-bg-danger ms-1'));
    if (s.cause_label) st.append(el('div', s.cause_label, 'small text-body-secondary mt-1'));
    const actions = el('div', null, 'd-flex gap-1 justify-content-end');
    actions.append(btn('', 'btn-outline-primary', async (e) => {
      const b = e.currentTarget; await guarded(() => busy(b, async () => { await api(`/servers/${s.id}/scan`, 'POST'); toast(`${s.name} 조회 완료`); await loadServers(); }));
    }, 'bi-arrow-repeat'));
    actions.lastChild.title = '조회'; actions.lastChild.setAttribute('aria-label', `${s.name} 조회`);
    tr.append(cell(name), cell(s.group, 'd-none d-md-table-cell'), cell(st),
      cell(String(s.certificate_count), 'd-none d-lg-table-cell text-end'),
      cell(s.last_scanned_at || '미조회', 'd-none d-lg-table-cell small'), cell(actions, 'text-end'));
    tb.append(tr);
  });
}
function renderSkeleton() {
  const tb = $('servers-body'); tb.replaceChildren();
  for (let i = 0; i < 3; i++) {
    const tr = document.createElement('tr');
    for (let j = 0; j < 6; j++) { const td = document.createElement('td'); td.append(el('div', null, 'skeleton')); tr.append(td); }
    tb.append(tr);
  }
}
async function loadServers() {
  if (!allServers.length) renderSkeleton();
  allServers = (await api('/servers')).servers;
  const groups = [...new Set(allServers.map((s) => s.group).filter(Boolean))].sort();
  const sel = $('filter-group'), cur = sel.value; sel.replaceChildren(new Option('전체 그룹', ''));
  groups.forEach((g) => sel.append(new Option(g, g))); sel.value = groups.includes(cur) ? cur : '';
  $('summary-time').textContent = `서버 ${allServers.length}대 · 갱신 ${new Date().toISOString().slice(0, 19)}Z`;
  renderStatCards(); renderTable();
  if (detailServerId && $('detail').classList.contains('show')) await renderDetail(detailServerId);
}

// ---------------------------------------------------------------- 상세 (오프캔버스)
async function openDetail(id) { detailServerId = id; await renderDetail(id); detailOffcanvas.show(); }
function daysBar(c) {
  if (c.remaining_days === null || c.remaining_days === undefined) return null;
  const pct = Math.max(4, Math.min(100, (c.remaining_days / 90) * 100));
  const tone = { OK: 'success', WARN: 'warning', EXPIRED: 'danger', CHAIN_RISK: 'danger' }[c.status] || 'secondary';
  const wrap = el('div', null, 'mt-2');
  wrap.append(el('div', c.status === 'EXPIRED' ? '만료됨' : `잔여 ${c.remaining_days}일`, 'small fw-semibold'));
  const p = el('div', null, 'progress thin'); const bar = el('div', null, `progress-bar bg-${tone}`);
  bar.style.width = `${pct}%`; p.append(bar); wrap.append(p); return wrap;
}
function kv(k, v, mono) {
  const row = el('div', null, 'row g-1 small');
  row.append(el('div', k, 'col-3 text-body-secondary'), el('div', v ?? '-', `col-9${mono ? ' mono' : ''}`));
  return row;
}
async function renderDetail(id) {
  const server = allServers.find((s) => s.id === id) || (await api('/servers')).servers.find((s) => s.id === id);
  const r = await api(`/servers/${id}/certificates`);
  $('detail-title').textContent = server.name;
  $('detail-meta').textContent = `${server.hostname}:${server.port} · 계정 ${server.account} · 경고 ${server.warn_days}일`;
  const body = $('detail-body'); body.replaceChildren();

  const head = el('div', null, 'd-flex align-items-center justify-content-between mb-3');
  head.append(badge(r.status), el('span', r.scanned_at ? `조회 ${r.scanned_at}` : '아직 조회하지 않았습니다', 'small text-body-secondary'));
  body.append(head);
  if (r.cause_label) {
    const a = el('div', null, 'alert alert-warning small');
    a.append(el('strong', r.cause_label), document.createTextNode(` — ${r.action}`)); body.append(a);
  }
  if (r.hostkey_blocked) {
    const a = el('div', null, 'alert alert-danger small');
    a.append(el('div', '호스트 키가 변경되어 조회가 차단되었습니다. 보안 이벤트일 수 있습니다.', 'mb-2'));
    if (me.role === 'admin') a.append(btn('변경을 확인했고 새 키를 신뢰', 'btn-danger', () => guarded(async () => {
      if (!confirm(`${server.name} 의 호스트 키 변경을 확인했고 새 키를 신뢰합니다.`)) return;
      await api(`/servers/${id}/hostkey/reset`, 'POST'); toast('다음 조회에서 새 호스트 키를 신뢰합니다.', 'warning'); }), 'bi-shield-exclamation'));
    body.append(a);
  }
  const acts = el('div', null, 'd-flex gap-2 mb-3');
  acts.append(btn('지금 조회', 'btn-primary', async (e) => {
    await guarded(() => busy(e.currentTarget, async () => { await api(`/servers/${id}/scan`, 'POST'); toast('조회 완료'); await loadServers(); }));
  }, 'bi-arrow-repeat'));
  if (me.role === 'admin') acts.append(btn('서버 삭제', 'btn-outline-danger', () => guarded(async () => {
    if (!confirm(`${server.name} 을(를) 삭제할까요?`)) return;
    await api(`/servers/${id}`, 'DELETE'); detailOffcanvas.hide(); toast('삭제했습니다.'); await loadServers(); }), 'bi-trash'));
  body.append(acts);

  const certs = r.certificates || [];
  if (!certs.length) body.append(el('div', r.scanned_at ? '발견된 인증서가 없습니다.' : '조회 버튼을 눌러 인증서를 수집하세요.', 'text-center text-body-secondary py-4'));
  certs.forEach((c) => {
    const card = el('div', null, `card cert-card s-${c.status} mb-3`); const b = el('div', null, 'card-body');
    const top = el('div', null, 'd-flex justify-content-between align-items-start gap-2');
    const title = el('div'); title.append(el('div', c.subject || '(파싱 불가)', 'fw-semibold text-break'), el('div', ROLE[c.role] || c.role, 'small text-body-secondary'));
    top.append(title, badge(c.status)); b.append(top);
    const bar = daysBar(c); if (bar) b.append(bar);
    if (c.note || c.cause_label) b.append(el('div', c.note || c.cause_label, 'small text-body-secondary mt-2'));
    if (c.changed) b.append(el('div', '이전 조회와 인증서 원문이 달라졌습니다.', 'small text-danger mt-1'));
    const d = el('div', null, 'mt-3 d-grid gap-1');
    d.append(kv('발급자', c.issuer), kv('SAN', (c.san || []).join(', ')), kv('유효 시작', c.not_before), kv('만료일', c.not_after),
      kv('지문', c.fingerprint_sha256, true), kv('발견 위치', (c.sources || []).join('\n')));
    b.append(d); card.append(b); body.append(card);
  });
  if ((r.suggested_paths || []).length) {
    const box = el('div', null, 'alert alert-secondary small');
    box.append(el('div', '웹 서버 설정에서 발견된 등록 후보 경로 (서버 등록의 "추가 조회 경로"에 추가하세요)', 'fw-semibold mb-1'));
    r.suggested_paths.forEach((p) => box.append(el('div', p, 'mono'))); body.append(box);
  }
}

// ---------------------------------------------------------------- 등록/감사/사용자/비밀번호
async function registerServer(e) {
  e.preventDefault();
  await guarded(async () => {
    await api('/servers', 'POST', {
      name: $('f-name').value.trim(), hostname: $('f-host').value.trim(), port: Number($('f-port').value),
      account: $('f-account').value.trim(), warn_days: Number($('f-warn').value || 30),
      paths: $('f-paths').value.split('\n').map((x) => x.trim()).filter(Boolean),
      tls_ports: $('f-tls').value.split(',').map((x) => x.trim()).filter(Boolean).map(Number),
      group: $('f-group').value.trim(), memo: $('f-memo').value.trim(), os_type: $('f-os').value,
    });
    $('server-form').reset(); updateOsHint(); $('f-port').value = 22; $('f-warn').value = 30;
    serverModal.hide(); toast('서버를 등록했습니다.'); await loadServers();
  });
}
// ---------------------------------------------------------------- 등록 전 연결 테스트 · 경로 탐지
function serverFormData() {
  return {
    hostname: $('f-host').value.trim(), port: Number($('f-port').value), account: $('f-account').value.trim(),
    paths: $('f-paths').value.split('\n').map((x) => x.trim()).filter(Boolean),
    tls_ports: $('f-tls').value.split(',').map((x) => x.trim()).filter(Boolean).map(Number), os_type: $('f-os').value,
  };
}
let osProfiles = [];
async function loadOsProfiles() {
  if (osProfiles.length) return;
  osProfiles = (await api('/os-profiles')).profiles;
  const sel = $('f-os'); sel.replaceChildren();
  osProfiles.forEach((p) => { const o = el('option', p.label); o.value = p.id; sel.append(o); });
  updateOsHint();
}
function updateOsHint() {
  const p = osProfiles.find((x) => x.id === $('f-os').value);
  $('f-os-hint').textContent = p && p.candidates.length
    ? `자동 조회 경로: ${p.candidates.join(', ')}`
    : '선택한 OS 계열의 표준 인증서 경로를 자동으로 조회합니다. 자동 감지는 접속 후 /etc/os-release 로 판단합니다.';
}
function addPathsToForm(paths) {
  const cur = $('f-paths').value.split('\n').map((x) => x.trim()).filter(Boolean);
  paths.forEach((p) => { if (!cur.includes(p)) cur.push(p); });
  $('f-paths').value = cur.join('\n');
}
function renderProbe(r) {
  const box = $('probe-result'); box.replaceChildren();
  const status = el('div', null, `alert ${r.connected ? 'alert-success' : 'alert-danger'} py-2 small mb-2`);
  if (r.connected) {
    status.append(icon('bi-check-circle-fill'), document.createTextNode(` SSH 연결 성공 (OpenSSH ${r.ssh_version || '버전 미확인'})`));
    if (r.supported === false) status.append(el('div', 'OpenSSH 7.0 미만은 지원 범위 밖이라 조회되지 않습니다(확인 필요로 표시).', 'mt-1'));
  } else {
    status.append(icon('bi-x-octagon-fill'), el('strong', ` ${r.cause_label}`), document.createTextNode(` — ${r.action}`));
    if (r.hostkey_blocked) status.append(el('div', '호스트 키가 이전과 다릅니다. 보안 이벤트일 수 있으니 확인 전까지 진행하지 마세요.', 'mt-1'));
  }
  box.append(status);
  if (r.connected && r.os) {
    const o = r.os, line = el('div', null, `small mb-2 ${o.mismatch ? 'text-danger' : 'text-body-secondary'}`);
    line.append(icon(o.mismatch ? 'bi-exclamation-triangle-fill' : 'bi-pc-display'),
      document.createTextNode(` 감지된 OS: ${o.detected || '확인 불가'} · 사용 프로필: ${o.label}${o.mode === 'auto' ? ' (자동)' : ' (선택)'}`));
    if (o.mismatch) line.append(el('div', `선택한 OS 와 실제 서버가 다릅니다. '${o.detected_profile}' 계열로 바꾸는 것을 권장합니다.`, 'mt-1'));
    box.append(line);
  }
  (r.tls || []).forEach((t) => {
    const line = el('div', null, `small mb-1 ${t.ok ? 'text-success' : 'text-danger'}`);
    line.append(icon(t.ok ? 'bi-check-circle' : 'bi-x-circle'),
      document.createTextNode(t.ok ? ` TLS ${t.port}: ${t.subject} (만료 ${t.not_after})` : ` TLS ${t.port}: ${t.cause_label} — ${t.action}`));
    box.append(line);
  });
  if (r.standard_paths.length) {
    const d = el('div', null, 'small mb-2'); d.append(el('div', '자동 조회되는 경로 (추가 불필요)', 'fw-semibold'));
    r.standard_paths.forEach((p) => d.append(el('div', `${p.path} — 인증서 파일 ${p.files}개`, 'mono text-body-secondary')));
    box.append(d);
  } else if (r.connected && r.supported !== false) {
    box.append(el('div', '표준 경로에서 인증서 파일을 찾지 못했습니다. 아래 제안이나 직접 입력한 경로를 사용하세요.', 'small text-body-secondary mb-2'));
  }
  if (r.suggested_paths.length) {
    const d = el('div', null, 'small'); d.append(el('div', '웹 서버 설정에서 발견한 경로 (선택해 추가)', 'fw-semibold mb-1'));
    const boxes = [];
    r.suggested_paths.forEach((s, i) => {
      const row = el('div', null, 'form-check'); const cb = el('input', null, 'form-check-input'); cb.type = 'checkbox'; cb.id = `sg-${i}`; cb.checked = true; cb.value = s.path;
      const lb = el('label', s.path, 'form-check-label mono'); lb.htmlFor = cb.id;
      if (!s.in_standard_root) lb.append(el('span', ' 표준 위치 밖', 'badge text-bg-warning ms-2'));
      row.append(cb, lb); d.append(row); boxes.push(cb);
    });
    d.append(btn('선택한 경로 추가', 'btn-primary mt-2', () => { addPathsToForm(boxes.filter((b) => b.checked).map((b) => b.value)); toast('조회 경로에 추가했습니다.'); }, 'bi-plus-lg'));
    d.append(el('div', '이 단계에서는 해당 경로를 읽지 않습니다. 등록 후 조회할 때 확인됩니다.', 'text-body-secondary mt-1'));
    box.append(d);
  }
}
async function probeServer() {
  const data = serverFormData();
  if (!data.hostname || !data.account) { toast('호스트와 조회 계정을 먼저 입력하세요.', 'warning'); return; }
  await guarded(() => busy($('btn-probe'), async () => renderProbe(await api('/servers/probe', 'POST', data))));
}

async function loadAudit() {
  const { logs } = await api('/audit-logs?limit=200');
  const tb = $('audit-body'); tb.replaceChildren();
  const sec = (t) => t.startsWith('security') || t === 'login_failed' || t.startsWith('mfa_');
  logs.forEach((l) => {
    const tr = document.createElement('tr'); if (sec(l.event_type)) tr.className = 'table-danger';
    const ev = el('code', l.event_type);
    tr.append(cell(l.timestamp.slice(0, 19) + 'Z', 'small text-nowrap'), cell(ev), cell((l.details || {}).actor), cell(l.description));
    tb.append(tr);
  });
  if (!logs.length) { const tr = document.createElement('tr'); const td = el('td', '기록이 없습니다.', 'text-center text-body-secondary py-4'); td.colSpan = 4; tr.append(td); tb.append(tr); }
}
async function verifyAudit() {
  const r = await api('/audit-logs/verify'); const s = $('audit-integrity'); s.replaceChildren();
  s.className = 'small fw-semibold ' + (r.integrity_valid ? 'text-success' : 'text-danger');
  s.append(icon(r.integrity_valid ? 'bi-check-circle-fill' : 'bi-exclamation-octagon-fill'),
    document.createTextNode(r.integrity_valid ? ` 무결성 정상 (${r.total_logs}건)` : ` 변조 의심 ${r.issues.length}건`));
}
async function loadDebug() {
  const [chk, ev] = await Promise.all([api('/debug/selfcheck'),
    api(`/debug/events?limit=300${$('dbg-errors').checked ? '&level=warning' : ''}${$('dbg-run').value ? `&run_id=${encodeURIComponent($('dbg-run').value)}` : ''}`)]);
  const cl = $('dbg-checks'); cl.replaceChildren();
  chk.checks.forEach((c) => {
    const li = el('li', null, 'list-group-item d-flex gap-2');
    li.append(icon(c.ok ? 'bi-check-circle-fill text-success' : 'bi-x-octagon-fill text-danger'), el('strong', c.name),
      el('span', [c.detail, c.hint].filter(Boolean).join(' — '), 'text-body-secondary small'));
    cl.append(li);
  });
  const tb = $('dbg-body'); tb.replaceChildren();
  ev.events.slice().reverse().forEach((e) => {
    const tr = document.createElement('tr'); if (e.level === 'error') tr.className = 'table-danger'; else if (e.level === 'warning') tr.className = 'table-warning';
    const extra = Object.entries(e).filter(([k]) => !['seq', 'ts', 'run_id', 'component', 'step', 'level', 'ms'].includes(k)).map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(' ');
    const run = el('a', e.run_id || '-', 'small'); run.href = '#'; run.addEventListener('click', (x) => { x.preventDefault(); $('dbg-run').value = e.run_id || ''; guarded(loadDebug); });
    tr.append(cell(e.ts.slice(11, 23), 'small text-nowrap'), cell(run), cell(`${e.component}/${e.step}`, 'text-nowrap'), cell(e.ms != null ? `${e.ms}ms` : '', 'small text-end'), cell(extra, 'small text-break'));
    tb.append(tr);
  });
  if (!ev.events.length) { const tr = document.createElement('tr'); const td = el('td', '이벤트가 없습니다. 연결 테스트·조회를 실행해 보세요.', 'text-center text-body-secondary py-4'); td.colSpan = 5; tr.append(td); tb.append(tr); }
}
// ---------------------------------------------------------------- 발급·배포 설정(certdeploy)
let cdOverview = null;
function fmtDays(d) { return d == null ? '-' : `${Math.floor(d)}일`; }
async function loadCd() {
  const banner = $('cd-banner'); banner.hidden = true; $('cd-body').hidden = false;
  try { cdOverview = await api('/certdeploy/overview'); } catch (e) { banner.textContent = e.message; banner.hidden = false; $('cd-body').hidden = true; return; }
  const o = cdOverview, m = o.mail;
  $('cd-mail-source').textContent = m ? `출처: ${m.source}` : '설정 없음';
  if (m) {
    $('m-enabled').checked = m.enabled !== false; $('m-host').value = m.host || ''; $('m-port').value = m.port || 587; $('m-starttls').checked = m.starttls !== false;
    $('m-from').value = m.from || ''; $('m-to').value = (m.to || []).join(', '); $('m-user').value = m.username || ''; $('m-success').checked = m.on_success !== false;
    $('m-sev').value = m.min_severity || 'info';
    $('m-pass').value = ''; $('m-pass-hint').textContent = m.password_set ? '비밀번호가 저장되어 있습니다. 비워 두면 유지합니다(화면에는 표시되지 않음).' : '비밀번호가 설정되어 있지 않습니다(인증 없는 릴레이면 비워 두세요).';
  }
  const box = $('cd-certs'); box.replaceChildren();
  o.certificates.forEach((c) => box.append(certCard(c)));
  fillChannels(o);
  await loadApprovals();
}
// ---- 알림 채널(웹훅·티켓·공통)
function chResult(id, ok, msg) { const s = $(id); s.className = `small fw-semibold ${ok ? 'text-success' : 'text-danger'}`; s.textContent = msg; }
function fillChannels(o) {
  const w = o.webhook;
  $('cd-wh-source').textContent = w ? `출처: ${w.source}` : '설정 없음';
  $('w-enabled').checked = !!(w && w.enabled !== false); $('w-format').value = (w && w.format) || 'teams'; $('w-sev').value = (w && w.min_severity) || 'info';
  $('w-success').checked = !!(w && w.on_success); $('w-url').value = '';
  $('w-url-hint').textContent = w && w.url_set ? '주소가 저장되어 있습니다. 비워 두면 유지합니다(화면에는 표시되지 않음).' : '주소 안에 토큰이 들어 있어 비밀로 취급합니다. 저장된 주소가 없습니다.';
  const i = o.itsm;
  $('cd-it-source').textContent = i ? `출처: ${i.source}` : '설정 없음';
  $('i-enabled').checked = !!(i && i.enabled !== false); $('i-format').value = (i && i.format) || 'servicenow'; $('i-url').value = (i && i.url) || '';
  $('i-auth').value = (i && i.auth) || 'basic'; $('i-user').value = (i && i.username) || ''; $('i-pass').value = ''; $('i-token').value = '';
  $('i-sev').value = (i && i.min_severity) || 'warning'; $('i-project').value = (i && i.project) || ''; $('i-type').value = (i && i.issue_type) || '';
  $('i-transition').value = (i && i.resolve_transition_id) || ''; $('i-group').value = (i && i.assignment_group) || ''; $('i-category').value = (i && i.category) || '';
  $('i-ca').value = (i && i.ca_file) || ''; $('i-verify').checked = !i || i.verify_tls !== false;
  $('i-secret-hint').textContent = i && (i.password_set || i.token_set) ? '비밀번호/토큰이 저장되어 있습니다. 비워 두면 유지합니다(화면에는 표시되지 않음).' : '저장된 비밀번호/토큰이 없습니다.';
  const nc = o.notify_common || {};
  $('cd-nc-source').textContent = `출처: ${nc.source || '-'}`; $('n-repeat').value = nc.repeat_hours || 0;
}
function whPayload() { return { enabled: $('w-enabled').checked, format: $('w-format').value, url: $('w-url').value.trim(), min_severity: $('w-sev').value, on_success: $('w-success').checked }; }
function itPayload() {
  return { enabled: $('i-enabled').checked, format: $('i-format').value, url: $('i-url').value.trim(), auth: $('i-auth').value, username: $('i-user').value.trim(),
    password: $('i-pass').value, token: $('i-token').value, min_severity: $('i-sev').value, project: $('i-project').value.trim(), issue_type: $('i-type').value.trim(),
    resolve_transition_id: $('i-transition').value.trim(), assignment_group: $('i-group').value.trim(), category: $('i-category').value.trim(),
    ca_file: $('i-ca').value.trim(), verify_tls: $('i-verify').checked };
}
function wireChannels() {
  $('cd-wh-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(() => busy($('btn-wh-save'), async () => { await api('/certdeploy/settings', 'PUT', { webhook: whPayload() }); chResult('cd-wh-result', true, '저장했습니다.'); toast('웹훅 설정을 저장했습니다.'); await loadCd(); })); });
  $('btn-wh-test').addEventListener('click', () => { chResult('cd-wh-result', true, '시험 메시지를 보내는 중…'); guarded(() => busy($('btn-wh-test'), async () => { const r = await api('/certdeploy/webhook-test', 'POST', whPayload()); chResult('cd-wh-result', r.ok, r.message); })); });
  $('cd-it-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(() => busy($('btn-it-save'), async () => { await api('/certdeploy/settings', 'PUT', { itsm: itPayload() }); chResult('cd-it-result', true, '저장했습니다.'); toast('티켓 연동 설정을 저장했습니다.'); await loadCd(); })); });
  $('btn-it-test').addEventListener('click', () => { chResult('cd-it-result', true, '접속을 확인하는 중…'); guarded(() => busy($('btn-it-test'), async () => { const r = await api('/certdeploy/itsm-test', 'POST', itPayload()); chResult('cd-it-result', r.ok, r.message); })); });
  $('cd-nc-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(() => busy($('btn-nc-save'), async () => { await api('/certdeploy/settings', 'PUT', { notify_common: { repeat_hours: Number($('n-repeat').value || 0) } }); chResult('cd-nc-result', true, '저장했습니다.'); toast('공통 알림 설정을 저장했습니다.'); await loadCd(); })); });
}
async function loadBackup() {
  const b = await api('/certdeploy/backup');
  $('cd-backup-card').hidden = false;
  const box = $('cd-bk-body'); box.replaceChildren();
  const badge = $('cd-bk-badge');
  if (!b.configured) { badge.className = 'badge text-bg-secondary ms-2'; badge.textContent = '설정 안 됨'; box.append(el('div', '설정 파일에 backup: 항목이 없습니다. 설치 매뉴얼 10-4 의 예시를 추가하세요.', 'text-warning')); return; }
  const l = b.last;
  badge.className = `badge ms-2 ${l && l.ok && !b.stale ? 'text-bg-success' : 'text-bg-danger'}`;
  badge.textContent = !l ? '백업 기록 없음' : (b.stale ? (l.ok ? '오래됨' : '실패') : (l.partial ? '일부 누락' : '정상'));
  const row = (k, v) => { const d = el('div', null, 'mb-1'); d.append(el('strong', k + ' '), document.createTextNode(v)); box.append(d); };
  row('마지막 실행', l ? `${l.finished.slice(0, 16).replace('T', ' ')} (${b.age_hours}시간 전) · ${l.ok ? '성공' : '실패'} · ${(l.size / 1048576).toFixed(2)} MB · 항목 ${l.members}개${l.verified ? ' · 복호화 검증됨' : ''}` : '없음 — 서버에서 certdeploy backup-run 을 실행하세요');
  if (l && l.error) row('오류', l.error);
  if (l && l.partial) row('빠진 항목', l.skipped.slice(0, 5).join('; '));
  (l ? l.copies : []).forEach((c) => row(`외부 복사 ${c.name}`, c.ok ? '성공' : `실패 — ${c.error}`));
  row('보관 위치', `${b.dir} · 매일 ${b.keep.daily}개, 주 ${b.keep.weekly}개, 월 ${b.keep.monthly}개 유지`);
  row('외부 대상', b.copy_to.length ? b.copy_to.map((t) => `${t.name}(${t.kind === 'ssh' ? t.host + ':' : ''}${t.path})`).join(', ') : '없음 — 같은 서버에만 있으면 서버 장애 때 함께 사라집니다');
  if (b.backups.length) row('최근 백업', b.backups.slice(0, 5).map((x) => `${x.name} (${(x.size / 1048576).toFixed(1)}MB)`).join(' · '));
}
const APPROVAL_LABEL = { pending: '승인 대기', approved: '승인됨(배포 대기)', applied: '배포 완료', rejected: '반려', expired: '만료', superseded: '새 인증서로 대체', bypassed: '긴급 우회' };
async function loadApprovals() {
  const { certificates } = await api('/certdeploy/approvals');
  const used = certificates.filter((c) => c.policy);
  $('cd-approvals-card').hidden = !used.length;
  const box = $('cd-approvals'); box.replaceChildren();
  used.forEach((c) => {
    const wrap = el('div', null, 'border rounded p-3');
    wrap.append(el('strong', c.cert), el('span', ` · 승인 ${c.policy.approvers}명 필요 · 유효 ${c.policy.ttl_hours}시간`, 'small text-body-secondary ms-2'));
    if (!c.requests.length) wrap.append(el('div', '승인 요청 이력이 없습니다.', 'small text-body-secondary mt-2'));
    c.requests.forEach((r) => {
      const row = el('div', null, 'd-flex flex-wrap align-items-center gap-2 mt-2 small');
      const open = r.status === 'pending';
      row.append(el('span', APPROVAL_LABEL[r.status] || r.status, `badge ${open ? 'text-bg-warning' : r.status === 'approved' ? 'text-bg-info' : r.status === 'applied' ? 'text-bg-success' : 'text-bg-secondary'}`),
        el('code', `일련번호 …${(r.serial || '').slice(-10)}`), el('span', `승인 ${r.approvals.length}/${r.needed} (${r.approvals.map((a) => a.by).join(', ') || '-'})`),
        el('span', `요청 ${r.requested_at.slice(0, 16).replace('T', ' ')} · ${r.requested_by}`, 'text-body-secondary'));
      if (open) {
        const mine = r.approvals.some((a) => a.by === me.username);
        const act = el('span', null, 'ms-auto d-flex gap-1');
        act.append(btn(mine ? '승인함' : '승인', 'btn-outline-success', () => guarded(async () => { await api(`/certdeploy/approvals/${r.id}/approve`, 'POST', {}); toast('승인했습니다.'); loadApprovals(); }), 'bi-check2'),
          btn('반려', 'btn-outline-danger', () => guarded(async () => { const reason = prompt('반려 사유(선택)') ; if (reason === null) return; await api(`/certdeploy/approvals/${r.id}/reject`, 'POST', { comment: reason }); toast('반려했습니다.'); loadApprovals(); }), 'bi-x'));
        if (mine) act.firstChild.disabled = true;
        row.append(act);
      }
      wrap.append(row);
    });
    box.append(wrap);
  });
}
function certCard(c) {
  const card = el('div', null, 'border rounded p-3');
  const head = el('div', null, 'd-flex flex-wrap justify-content-between gap-2 mb-2');
  head.append(el('strong', c.name, 'fs-6'));
  const info = el('div', null, 'small text-body-secondary');
  info.textContent = c.cert ? `일련번호 ${c.cert.serial.slice(0, 12)}… · 만료 ${c.cert.not_after.slice(0, 10)} (남은 ${fmtDays(c.cert.days_left)}) · ${c.cert.names.join(', ')}` : (c.cert_error || '인증서 없음(아직 발급·가져오기 전)');
  head.append(info); card.append(head);
  const meta = el('div', null, 'small mb-2');
  meta.textContent = `대상 ${c.targets.length}개` + (c.dns_mode ? ` · 발급 DNS 방식 ${c.dns_mode}` : '') + (c.last_run ? ` · 마지막 실행 ${(c.last_run.finished_at || '').slice(0, 16).replace('T', ' ')} ${c.last_run.ok ? '정상' : '문제 있음'}` : ' · 실행 기록 없음');
  card.append(meta);
  if (c.last_run) {
    const row = el('div', null, 'd-flex flex-wrap gap-1 mb-2');
    c.last_run.results.forEach((r) => { const bad = ['failed', 'rolled_back'].includes(r.status); const wait = r.status === 'manual_pending';
      row.append(el('span', `${r.target}: ${r.status}`, `badge ${bad ? 'text-bg-danger' : wait ? 'text-bg-warning' : 'text-bg-success'}`)); });
    card.append(row);
  }
  const keyBox = el('div', null, 'bg-body-tertiary rounded p-2');
  const state = c.key_file_encrypted === null ? '키 파일 없음' : c.key_file_encrypted ? '암호화됨' : '평문(권한 600)';
  keyBox.append(el('div', `개인키 보호 — 현재 파일: ${state} · 설정: ${c.key_encryption === 'passphrase' ? '사용' : '사용 안 함'} (${c.key_encryption_source})`, 'small fw-semibold mb-2'));
  const radios = el('div', null, 'd-flex gap-3 mb-2');
  ['passphrase', 'none'].forEach((v) => {
    const wrap = el('div', null, 'form-check'); const r = el('input', null, 'form-check-input'); r.type = 'radio'; r.name = `kp-${c.name}`; r.id = `kp-${c.name}-${v}`; r.value = v; r.checked = c.key_encryption === v;
    const l = el('label', v === 'passphrase' ? '사용 (암호로 보호)' : '사용 안 함', 'form-check-label'); l.htmlFor = r.id; wrap.append(r, l); radios.append(wrap);
  });
  keyBox.append(radios);
  const pw = el('div', null, 'row g-2 align-items-end');
  const c1 = el('div', null, 'col-md-4'); const p1 = el('input', null, 'form-control form-control-sm'); p1.type = 'password'; p1.autocomplete = 'new-password'; p1.placeholder = c.passphrase_set ? '암호(비우면 저장된 암호 유지)' : '암호 12자 이상'; p1.setAttribute('aria-label', `${c.name} 개인키 암호`); c1.append(p1);
  const c2 = el('div', null, 'col-md-4'); const p2 = el('input', null, 'form-control form-control-sm'); p2.type = 'password'; p2.autocomplete = 'new-password'; p2.placeholder = '암호 확인'; p2.setAttribute('aria-label', `${c.name} 개인키 암호 확인`); c2.append(p2);
  const c3 = el('div', null, 'col-md-4');
  const apply = btn('적용', 'btn-sm btn-primary', async (e) => {
    const mode = card.querySelector(`input[name="kp-${c.name}"]:checked`).value;
    if (mode === 'passphrase' && p1.value !== p2.value) { toast('암호와 암호 확인이 다릅니다.', 'warning'); return; }
    if (mode === 'passphrase' && !p1.value && !c.passphrase_set) { toast('암호를 입력하세요(12자 이상).', 'warning'); return; }
    if (!window.confirm(`${c.name} 인증서의 개인키 보호를 '${mode === 'passphrase' ? '사용' : '사용 안 함'}'으로 적용합니다. 키 파일이 바로 변환됩니다. 계속할까요?`)) return;
    await guarded(() => busy(e.currentTarget, async () => {
      const r = await api('/certdeploy/settings', 'PUT', { certificates: { [c.name]: { key_encryption: mode, ...(p1.value ? { key_passphrase: p1.value } : {}) } } });
      p1.value = p2.value = ''; toast((r.messages || ['저장했습니다']).join(' / ')); await loadCd();
    }));
  }, 'bi-check2');
  c3.append(apply); pw.append(c1, c2, c3); keyBox.append(pw);
  keyBox.append(el('div', '암호는 서버(설정 화면 파일, 권한 600)에 저장되어 배포·갱신 때 자동으로 쓰입니다. 파일만 유출되는 경우를 막는 장치이며, 서버 자체가 침해되는 것까지 막지는 못합니다.', 'form-text'));
  card.append(keyBox);
  return card;
}
function mailPayload() {
  return { enabled: $('m-enabled').checked, host: $('m-host').value.trim(), port: Number($('m-port').value || 587), starttls: $('m-starttls').checked,
    from: $('m-from').value.trim(), to: $('m-to').value, username: $('m-user').value.trim(), password: $('m-pass').value, on_success: $('m-success').checked, min_severity: $('m-sev').value };
}
function mailResult(ok, msg) { const s = $('cd-mail-result'); s.className = `small fw-semibold ${ok ? 'text-success' : 'text-danger'}`; s.textContent = msg; }
async function saveMail(e) {
  e.preventDefault();
  await guarded(() => busy($('btn-mail-save'), async () => { await api('/certdeploy/settings', 'PUT', { mail: mailPayload() }); mailResult(true, '저장했습니다.'); toast('메일 설정을 저장했습니다.'); await loadCd(); }));
}
async function testMail() {
  mailResult(true, '시험 메일을 보내는 중…');
  await guarded(() => busy($('btn-mail-test'), async () => { const r = await api('/certdeploy/mail-test', 'POST', mailPayload()); mailResult(r.ok, r.message); }));
}

// ---------------------------------------------------------------- 2단계 인증(TOTP)
async function openMfa() {
  const m = await api('/auth/mfa');
  ['mfa-off', 'mfa-setup', 'mfa-codes-box', 'mfa-on'].forEach((id) => { $(id).hidden = true; });
  ['mfa-start-form', 'mfa-enable-form', 'mfa-disable-form'].forEach((id) => $(id).reset());
  if (m.enabled) {
    $('mfa-on').hidden = false; $('mfa-recovery-left').textContent = `남은 복구 코드 ${m.recovery_remaining}개`;
    $('mfa-disable-form').hidden = m.required;
  } else { $('mfa-off').hidden = false; }
  mfaModal.show();
}
async function mfaStart() {
  const r = await api('/auth/mfa/setup', 'POST', { password: $('mfa-pw').value });
  $('mfa-secret').textContent = r.secret.replace(/(.{4})/g, '$1 ').trim(); $('mfa-uri').textContent = r.uri;
  $('mfa-off').hidden = true; $('mfa-setup').hidden = false;
}
async function mfaEnable() {
  const r = await api('/auth/mfa/enable', 'POST', { code: $('mfa-code').value });
  $('mfa-codes').textContent = r.recovery_codes.join('\n');
  $('mfa-setup').hidden = true; $('mfa-codes-box').hidden = false; toast('2단계 인증을 켰습니다.');
}
async function mfaDisable() {
  await api('/auth/mfa/disable', 'POST', { password: $('mfa-dpw').value, code: $('mfa-dcode').value });
  mfaModal.hide(); toast('2단계 인증을 껐습니다.');
}

async function loadUsers() {
  const { users } = await api('/users'); const tb = $('users-body'); tb.replaceChildren();
  users.forEach((u) => {
    const a = el('div', null, 'd-flex gap-1 justify-content-end');
    if (u.mfa) a.append(btn('2단계 인증 초기화', 'btn-outline-secondary', () => guarded(async () => { if (confirm(`${u.username} 의 2단계 인증을 초기화합니다(기기 분실 시). 해당 계정의 로그인 세션도 끊깁니다. 계속할까요?`)) { await api(`/users/${u.username}/mfa/reset`, 'POST'); toast('초기화했습니다. 다음 로그인 후 다시 등록하게 안내하세요.'); loadUsers(); } }), 'bi-shield-x'));
    if (u.locked_until) a.append(btn('잠금 해제', 'btn-outline-warning', () => guarded(async () => { await api(`/users/${u.username}/unlock`, 'POST'); loadUsers(); }), 'bi-unlock'));
    if (u.username !== me.username) a.append(btn('삭제', 'btn-outline-danger', () => guarded(async () => { if (confirm(`${u.username} 삭제?`)) { await api(`/users/${u.username}`, 'DELETE'); loadUsers(); } }), 'bi-trash'));
    const role = el('span', u.role === 'admin' ? '관리자' : '운영자', `badge ${u.role === 'admin' ? 'text-bg-primary' : 'text-bg-secondary'}`);
    const tr = document.createElement('tr');
    tr.append(cell(u.username), cell(role), cell(u.mfa ? '켜짐' : '꺼짐', u.mfa ? 'text-success' : 'text-muted'), cell(u.locked_until ? `${u.locked_until} 까지` : '-'), cell(a, 'text-end')); tb.append(tr);
  });
}

// ---------------------------------------------------------------- 초기화
function syncThemeIcon() { $('theme-toggle').replaceChildren(icon(window.cpIsDark() ? 'bi-sun' : 'bi-moon-stars')); }

document.addEventListener('DOMContentLoaded', async () => {
  detailOffcanvas = new bootstrap.Offcanvas($('detail'));
  serverModal = new bootstrap.Modal($('server-modal'));
  pwModal = new bootstrap.Modal($('pw-modal'));
  mfaModal = new bootstrap.Modal($('mfa-modal'));
  $('open-mfa').addEventListener('click', (e) => { e.preventDefault(); openMfa(); });
  $('mfa-start-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(mfaStart); });
  $('mfa-enable-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(mfaEnable); });
  $('mfa-disable-form').addEventListener('submit', (e) => { e.preventDefault(); guarded(mfaDisable); });
  $('mfa-copy-codes').addEventListener('click', () => navigator.clipboard && navigator.clipboard.writeText($('mfa-codes').textContent).then(() => toast('복사했습니다.')));
  syncThemeIcon();
  $('theme-toggle').addEventListener('click', () => { window.cpSetTheme(!window.cpIsDark(), true); syncThemeIcon(); });

  Object.entries(STATUS).forEach(([k, v]) => $('filter-status').append(new Option(v.label, k)));
  ['filter-text', 'filter-status', 'filter-group'].forEach((id) => $(id).addEventListener('input', renderTable));
  $('filter-reset').addEventListener('click', () => { $('filter-text').value = ''; $('filter-status').value = ''; $('filter-group').value = ''; cardFilter = null; renderStatCards(); renderTable(); });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault(); $('login-error').textContent = '';
    await busy($('login-btn'), async () => {
      try { enter(await api('/auth/login', 'POST', { username: $('login-user').value, password: $('login-pass').value, code: $('login-code').value })); }
      catch (err) {
        if (err.code === 'mfa_required') { $('login-code-wrap').hidden = false; $('login-code').focus(); }
        $('login-error').textContent = err.message;
      }
    });
  });
  $('logout').addEventListener('click', async (e) => { e.preventDefault(); await api('/auth/logout', 'POST').catch(() => {}); allServers = []; showLogin(); });
  document.querySelectorAll('#main-tabs .nav-link').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); showView(a.dataset.view); }));
  $('btn-scan-all').addEventListener('click', (e) => guarded(() => busy(e.currentTarget, async () => { const r = await api('/scan', 'POST'); toast(`${r.scanned}대 조회 완료`); await loadServers(); })));
  $('btn-export').addEventListener('click', () => { window.location = '/export.csv'; });
  $('btn-verify').addEventListener('click', () => guarded(verifyAudit));
  $('cd-mail-form').addEventListener('submit', saveMail);
  wireChannels();
  $('btn-mail-test').addEventListener('click', testMail);
  $('btn-cd-refresh').addEventListener('click', () => guarded(loadCd));
  $('btn-dbg-refresh').addEventListener('click', () => guarded(loadDebug));
  $('dbg-errors').addEventListener('change', () => guarded(loadDebug));
  $('dbg-run').addEventListener('change', () => guarded(loadDebug));
  $('btn-dbg-bundle').addEventListener('click', () => { window.location = '/debug/bundle'; });
  $('server-form').addEventListener('submit', registerServer);
  $('btn-probe').addEventListener('click', probeServer);
  $('f-os').addEventListener('change', updateOsHint);
  $('server-modal').addEventListener('show.bs.modal', () => guarded(loadOsProfiles));
  $('server-modal').addEventListener('hidden.bs.modal', () => $('probe-result').replaceChildren());
  $('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await guarded(async () => { await api('/users', 'POST', { username: $('u-name').value, password: $('u-pass').value, role: $('u-role').value }); $('user-form').reset(); toast('사용자를 추가했습니다.'); loadUsers(); });
  });
  $('pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await guarded(async () => {
      await api('/auth/password', 'POST', { old_password: $('pw-old').value, new_password: $('pw-new').value });
      $('pw-form').reset(); pwModal.hide(); allServers = []; showLogin(); $('login-error').textContent = '비밀번호를 변경했습니다. 다시 로그인하세요.';
    });
  });
  try { enter(await api('/auth/me')); } catch { showLogin(); }
});
