// 설정·운영 화면 브라우저 스모크: node tests/ui_cd_smoke.js <baseUrl> <user> <password>  (실패 시 종료 코드 1)
const { chromium } = require('playwright');
(async () => {
  const [base, user, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'ko-KR' });
  const page = await ctx.newPage();
  const errs = [], fails = [];
  page.on('pageerror', (e) => errs.push(String(e)));
  page.on('response', (r) => { if (r.status() >= 500) errs.push(`http ${r.status()} ${r.url()}`); });
  const ok = (cond, msg) => { if (!cond) fails.push(msg); };
  await page.goto(base);
  await page.fill('#login-user', user); await page.fill('#login-pass', pass); await page.click('#login-btn');
  await page.waitForSelector('#app-view:not([hidden])');
  await page.click('[data-view="cd"]');
  await page.waitForSelector('#cd-home-checklist tr');
  ok((await page.locator('#cd-home-checklist tr').count()) >= 8, '체크리스트 항목 수');
  ok((await page.locator('#cd-home-cards .card').count()) === 5, '요약 카드 5개');
  ok((await page.locator('#cd-home-todo li').count()) >= 1, '지금 확인할 일');
  ok(/필수 \d+\/\d+ 완료/.test(await page.locator('#cd-home-progress').innerText()), '진행률 표시');
  // 탭 전환과 기본 표시
  for (const t of ['certs', 'notify', 'backup', 'home']) {
    await page.click(`[data-cd-tab="${t}"]`);
    ok(await page.locator(`[data-cd-pane="${t}"]`).isVisible(), `${t} 탭 표시`);
    ok((await page.locator('[data-cd-pane]:visible').count()) === 1, `${t} 탭만 표시`);
  }
  await page.click('[data-cd-tab="notify"]');
  ok((await page.locator('#cd-channel-rows tr').count()) === 3, '채널 요약 3행');
  ok((await page.locator('#cd-mail-collapse.show').count()) === 0, '메일 설정은 처음에 접힘');
  // 체크리스트 → 이동 버튼이 해당 설정을 펼친다
  await page.click('[data-cd-tab="home"]');
  await page.locator('#cd-home-checklist tr', { hasText: '메일을 설정했다' }).locator('button').click();
  await page.waitForTimeout(500);
  ok(await page.locator('[data-cd-pane="notify"]').isVisible(), '이동 후 알림 탭');
  ok((await page.locator('#cd-mail-collapse.show').count()) === 1, '이동 후 메일 설정 펼침');
  // 인증서·승인, 백업 내용
  await page.click('[data-cd-tab="certs"]');
  ok(await page.locator('#cd-approvals-card').isVisible(), '승인 카드 표시');
  await page.click('[data-cd-tab="backup"]');
  ok((await page.locator('#cd-bk-body').innerText()).includes('보관 위치'), '백업 카드 내용');
  // 감사 로그: 한글 이벤트 이름
  await page.click('[data-view="audit"]'); await page.waitForTimeout(600);
  ok((await page.locator('#audit-body').innerText()).includes('로그인'), '감사 로그 한글 라벨');
  // 모바일 폭에서 가로 넘침 없음
  await page.setViewportSize({ width: 390, height: 800 });
  await page.click('.navbar-toggler'); await page.waitForTimeout(300); await page.click('[data-view="cd"]'); await page.waitForTimeout(500);
  for (const t of ['home', 'certs', 'notify', 'backup']) {
    await page.click(`[data-cd-tab="${t}"]`); await page.waitForTimeout(200);
    ok(!(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2)), `모바일 ${t} 가로 넘침 없음`);
  }
  await browser.close();
  if (errs.length) fails.push('페이지 오류: ' + errs.join(' | '));
  if (fails.length) { console.error('FAIL\n' + fails.join('\n')); process.exit(1); }
  console.log('UI_OK');
})().catch((e) => { console.error(e); process.exit(1); });
