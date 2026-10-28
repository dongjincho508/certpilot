/** CertPilot 관리 화면: 인증 + 현황/등록/감사/사용자. 모든 값은 textContent 로만 삽입한다(XSS 방지). */
'use strict';

const $ = (id) => document.getElementById(id);
const STATUS = {
  OK: ['정상', 'badge-valid'], WARN: ['만료 임박', 'badge-warning'], EXPIRED: ['만료', 'badge-expired'],
  CHAIN_RISK: ['체인 위험', 'badge-danger'], NOT_YET: ['유효 전(미발급)', 'badge-other'],
  FETCH_FAIL: ['조회 실패', 'badge-danger'], NOT_FOUND: ['인증서 미발견', 'badge-other'],
  UNKNOWN: ['확인 필요', 'badge-unknown'],
};
let me = null;

async function api(path, method = 'GET', body = null) {
  const opt = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
  if (body !== null) opt.body = JSON.stringify(body);
  const res = await fetch(path, opt);
  if (res.status === 401 && path !== '/auth/login') { showLogin(); throw new Error('로그인이 필요합니다.'); }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error && data.error.message) || `오류 ${res.status}`);
  return data;
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function badge(status) {
  const [label, cls] = STATUS[status] || ['미조회', 'badge-unknown'];
  return el('span', label, 'badge ' + cls);
}
function row(...cells) {
  const tr = document.createElement('tr');
  cells.forEach((c) => { const td = document.createElement('td'); td.append(c instanceof Node ? c : (c ?? '-')); tr.append(td); });
  return tr;
}
function flash(msg, kind = 'success') {
  const f = $('flash');
  f.textContent = msg; f.className = `alert alert-${kind}`;
  setTimeout(() => f.classList.add('d-none'), 6000);
}
function btn(text, cls, fn) { const b = el('button', text, `btn btn-sm ${cls}`); b.addEventListener('click', fn); return b; }
async function guarded(fn) { try { await fn(); } catch (e) { flash(e.message, 'danger'); } }

// ---------------------------------------------------------------- 화면 전환
function showLogin() { me = null; $('app-view').hidden = true; $('login-view').hidden = false; }
function showView(name) {
  document.querySelectorAll('main section').forEach((s) => { s.hidden = s.id !== `view-${name}`; });
  document.querySelectorAll('.sidebar .nav-link[data-view]').forEach((a) => a.classList.toggle('active', a.dataset.view === name));
  if (name === 'dashboard') loadServers();
  if (name === 'audit') loadAudit();
  if (name === 'users') loadUsers();
}
async function enter(user) {
  me = user; $('login-view').hidden = true; $('app-view').hidden = false;
  $('whoami').textContent = `${user.username} (${user.role === 'admin' ? '관리자' : '운영자'})`;
  document.querySelectorAll('.admin-only').forEach((e) => { e.hidden = user.role !== 'admin'; });
  showView('dashboard');
}

// ---------------------------------------------------------------- 현황
async function loadServers() {
  const q = new URLSearchParams();
  if ($('filter-status').value) q.set('status', $('filter-status').value);
  if ($('filter-group').value) q.set('group', $('filter-group').value);
  const { servers } = await api('/servers?' + q);
  const tb = $('servers-body'); tb.replaceChildren();
  const all = (await api('/servers')).servers;
  const c = { OK: 0, WARN: 0, risk: 0, other: 0 };
  all.forEach((s) => {
    if (s.status === 'OK') c.OK++; else if (s.status === 'WARN') c.WARN++;
    else if (s.status === 'EXPIRED' || s.status === 'CHAIN_RISK') c.risk++; else c.other++;
  });
  $('cnt-ok').textContent = c.OK; $('cnt-warn').textContent = c.WARN;
  $('cnt-expired').textContent = c.risk; $('cnt-other').textContent = c.other;
  $('summary-time').textContent = `서버 ${all.length}대 · 갱신 ${new Date().toISOString()}`;
  if (!servers.length) { tb.append(row('서버가 없습니다.')); return; }
  servers.forEach((s) => {
    const actions = el('div', null, 'd-flex gap-1');
    actions.append(btn('조회', 'btn-outline-primary', () => guarded(async () => { await api(`/servers/${s.id}/scan`, 'POST'); flash(`${s.name} 조회 완료`); await loadServers(); await showDetail(s); })));
    actions.append(btn('상세', 'btn-outline-secondary', () => guarded(() => showDetail(s))));
    if (s.hostkey_blocked && me.role === 'admin')
      actions.append(btn('호스트 키 재확인', 'btn-outline-warning', () => guarded(async () => {
        if (!confirm(`${s.name} 의 호스트 키 변경을 확인했고 새 키를 신뢰합니다.`)) return;
        await api(`/servers/${s.id}/hostkey/reset`, 'POST'); flash('다음 조회에서 새 호스트 키를 신뢰합니다.'); })));
    if (me.role === 'admin')
      actions.append(btn('삭제', 'btn-outline-danger', () => guarded(async () => {
        if (!confirm(`${s.name} 을(를) 삭제할까요?`)) return;
        await api(`/servers/${s.id}`, 'DELETE'); await loadServers(); })));
    const st = badge(s.status);
    if (s.cause_label) st.title = `${s.cause_label} — ${s.action}`;
    tb.append(row(s.name, `${s.hostname}:${s.port}`, s.group, st, String(s.certificate_count), s.last_scanned_at || '미조회', actions));
  });
}
async function showDetail(s) {
  const r = await api(`/servers/${s.id}/certificates`);
  $('detail-card').classList.remove('d-none');
  $('detail-title').textContent = `${s.name} 인증서 상세`;
  const tb = $('detail-body'); tb.replaceChildren();
  (r.certificates || []).forEach((c) => {
    const b = badge(c.status);
    if (c.note || c.cause_label) b.title = c.note || c.cause_label;
    const roles = { leaf: '리프', intermediate: '중간CA', root: '루트' };
    tb.append(row(b, roles[c.role] || c.role, c.subject, c.issuer, (c.san || []).join(', ') || '-',
      c.not_before, c.not_after, c.remaining_days === null ? '-' : `${c.remaining_days}일`, c.sources.join(', ')));
  });
  if (!(r.certificates || []).length) tb.append(row('인증서 없음 (조회 전이거나 미발견)'));
  $('detail-suggest').textContent = (r.suggested_paths || []).length
    ? '웹 서버 설정에서 발견된 등록 후보 경로: ' + r.suggested_paths.join(', ') : '';
}

// ---------------------------------------------------------------- 등록/감사/사용자
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
    flash('서버를 등록했습니다.'); showView('dashboard');
  });
}
async function loadAudit() {
  const { logs } = await api('/audit-logs?limit=200');
  const tb = $('audit-body'); tb.replaceChildren();
  logs.forEach((l) => tb.append(row(l.timestamp, l.event_type, (l.details || {}).actor, l.description)));
}
async function verifyAudit() {
  const r = await api('/audit-logs/verify');
  const s = $('audit-integrity');
  s.textContent = r.integrity_valid ? `무결성 정상 (${r.total_logs}건)` : `⚠ 변조 의심 ${r.issues.length}건`;
  s.className = 'small ' + (r.integrity_valid ? 'text-success' : 'text-danger');
}
async function loadUsers() {
  const { users } = await api('/users');
  const tb = $('users-body'); tb.replaceChildren();
  users.forEach((u) => {
    const a = el('div', null, 'd-flex gap-1');
    if (u.locked_until) a.append(btn('잠금 해제', 'btn-outline-warning', () => guarded(async () => { await api(`/users/${u.username}/unlock`, 'POST'); loadUsers(); })));
    if (u.username !== me.username) a.append(btn('삭제', 'btn-outline-danger', () => guarded(async () => { if (confirm(`${u.username} 삭제?`)) { await api(`/users/${u.username}`, 'DELETE'); loadUsers(); } })));
    tb.append(row(u.username, u.role === 'admin' ? '관리자' : '운영자', u.locked_until || '-', a));
  });
}

// ---------------------------------------------------------------- 초기화
document.addEventListener('DOMContentLoaded', async () => {
  Object.entries(STATUS).forEach(([k, [label]]) => { const o = el('option', label); o.value = k; $('filter-status').append(o); });
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault(); $('login-error').textContent = '';
    try { await enter(await api('/auth/login', 'POST', { username: $('login-user').value, password: $('login-pass').value })); $('login-pass').value = ''; }
    catch (err) { $('login-error').textContent = err.message; }
  });
  $('logout').addEventListener('click', async (e) => { e.preventDefault(); await api('/auth/logout', 'POST').catch(() => {}); showLogin(); });
  document.querySelectorAll('.sidebar .nav-link[data-view]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); showView(a.dataset.view); }));
  $('filter-status').addEventListener('change', () => guarded(loadServers));
  $('filter-group').addEventListener('change', () => guarded(loadServers));
  $('btn-scan-all').addEventListener('click', () => guarded(async () => { $('btn-scan-all').disabled = true; try { const r = await api('/scan', 'POST'); flash(`${r.scanned}대 조회 완료`); await loadServers(); } finally { $('btn-scan-all').disabled = false; } }));
  $('btn-export').addEventListener('click', () => { window.location = '/export.csv'; });
  $('btn-verify').addEventListener('click', () => guarded(verifyAudit));
  $('server-form').addEventListener('submit', registerServer);
  $('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await guarded(async () => { await api('/users', 'POST', { username: $('u-name').value, password: $('u-pass').value, role: $('u-role').value }); $('user-form').reset(); loadUsers(); });
  });
  try { await enter(await api('/auth/me')); } catch { showLogin(); }
});
