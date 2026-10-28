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
let detailOffcanvas, serverModal, pwModal;

async function api(path, method = 'GET', body = null) {
  const opt = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
  if (body !== null) opt.body = JSON.stringify(body);
  const res = await fetch(path, opt);
  if (res.status === 401 && !path.startsWith('/auth/')) { showLogin(); throw new Error('로그인이 필요합니다.'); }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error && data.error.message) || `오류 ${res.status}`);
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
}
function showView(name) {
  ['dashboard', 'audit', 'users'].forEach((v) => { $(`view-${v}`).hidden = v !== name; });
  document.querySelectorAll('#main-tabs .nav-link').forEach((a) => a.classList.toggle('active', a.dataset.view === name));
  if (name === 'dashboard') guarded(loadServers);
  if (name === 'audit') guarded(loadAudit);
  if (name === 'users') guarded(loadUsers);
}
function enter(user) {
  me = user; $('login-view').hidden = true; $('app-view').hidden = false;
  $('whoami').textContent = `${user.username} · ${user.role === 'admin' ? '관리자' : '운영자'}`;
  document.querySelectorAll('.admin-only').forEach((e) => { e.hidden = user.role !== 'admin'; });
  showView('dashboard');
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
      group: $('f-group').value.trim(), memo: $('f-memo').value.trim(),
    });
    $('server-form').reset(); $('f-port').value = 22; $('f-warn').value = 30;
    serverModal.hide(); toast('서버를 등록했습니다.'); await loadServers();
  });
}
// ---------------------------------------------------------------- 등록 전 연결 테스트 · 경로 탐지
function serverFormData() {
  return {
    hostname: $('f-host').value.trim(), port: Number($('f-port').value), account: $('f-account').value.trim(),
    paths: $('f-paths').value.split('\n').map((x) => x.trim()).filter(Boolean),
    tls_ports: $('f-tls').value.split(',').map((x) => x.trim()).filter(Boolean).map(Number),
  };
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
  const sec = (t) => t.startsWith('security') || t === 'login_failed';
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
async function loadUsers() {
  const { users } = await api('/users'); const tb = $('users-body'); tb.replaceChildren();
  users.forEach((u) => {
    const a = el('div', null, 'd-flex gap-1 justify-content-end');
    if (u.locked_until) a.append(btn('잠금 해제', 'btn-outline-warning', () => guarded(async () => { await api(`/users/${u.username}/unlock`, 'POST'); loadUsers(); }), 'bi-unlock'));
    if (u.username !== me.username) a.append(btn('삭제', 'btn-outline-danger', () => guarded(async () => { if (confirm(`${u.username} 삭제?`)) { await api(`/users/${u.username}`, 'DELETE'); loadUsers(); } }), 'bi-trash'));
    const role = el('span', u.role === 'admin' ? '관리자' : '운영자', `badge ${u.role === 'admin' ? 'text-bg-primary' : 'text-bg-secondary'}`);
    const tr = document.createElement('tr');
    tr.append(cell(u.username), cell(role), cell(u.locked_until ? `${u.locked_until} 까지` : '-'), cell(a, 'text-end')); tb.append(tr);
  });
}

// ---------------------------------------------------------------- 초기화
function syncThemeIcon() { $('theme-toggle').replaceChildren(icon(window.cpIsDark() ? 'bi-sun' : 'bi-moon-stars')); }

document.addEventListener('DOMContentLoaded', async () => {
  detailOffcanvas = new bootstrap.Offcanvas($('detail'));
  serverModal = new bootstrap.Modal($('server-modal'));
  pwModal = new bootstrap.Modal($('pw-modal'));
  syncThemeIcon();
  $('theme-toggle').addEventListener('click', () => { window.cpSetTheme(!window.cpIsDark(), true); syncThemeIcon(); });

  Object.entries(STATUS).forEach(([k, v]) => $('filter-status').append(new Option(v.label, k)));
  ['filter-text', 'filter-status', 'filter-group'].forEach((id) => $(id).addEventListener('input', renderTable));
  $('filter-reset').addEventListener('click', () => { $('filter-text').value = ''; $('filter-status').value = ''; $('filter-group').value = ''; cardFilter = null; renderStatCards(); renderTable(); });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault(); $('login-error').textContent = '';
    await busy($('login-btn'), async () => {
      try { enter(await api('/auth/login', 'POST', { username: $('login-user').value, password: $('login-pass').value })); }
      catch (err) { $('login-error').textContent = err.message; }
    });
  });
  $('logout').addEventListener('click', async (e) => { e.preventDefault(); await api('/auth/logout', 'POST').catch(() => {}); allServers = []; showLogin(); });
  document.querySelectorAll('#main-tabs .nav-link').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); showView(a.dataset.view); }));
  $('btn-scan-all').addEventListener('click', (e) => guarded(() => busy(e.currentTarget, async () => { const r = await api('/scan', 'POST'); toast(`${r.scanned}대 조회 완료`); await loadServers(); })));
  $('btn-export').addEventListener('click', () => { window.location = '/export.csv'; });
  $('btn-verify').addEventListener('click', () => guarded(verifyAudit));
  $('server-form').addEventListener('submit', registerServer);
  $('btn-probe').addEventListener('click', probeServer);
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
