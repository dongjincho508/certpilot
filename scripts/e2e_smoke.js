// 화면 스모크 테스트: node scripts/e2e_smoke.js [baseUrl] [screenshotDir]
const { chromium } = require('playwright');
(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8080';
  const out = process.argv[3] || '.';
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('dialog', (d) => d.accept());
  await page.goto(base);
  await page.waitForSelector('#login-form');
  await page.screenshot({ path: `${out}/1-login.png` });
  await page.fill('#login-user', 'admin');
  await page.fill('#login-pass', 'wrong');
  await page.click('#login-form button');
  await page.waitForFunction(() => document.getElementById('login-error').textContent.length > 0);
  await page.fill('#login-pass', 'Demo!Passw0rd-1234');
  await page.click('#login-form button');
  await page.waitForSelector('#servers-body tr td .badge');
  const rows = await page.$$eval('#servers-body tr', (trs) => trs.map((t) => t.innerText.replace(/\s+/g, ' ')));
  console.log('rows:', JSON.stringify(rows));
  await page.screenshot({ path: `${out}/2-dashboard.png` });
  await page.click('#servers-body tr:first-child td:first-child');
  await page.waitForSelector('#detail.show .cert-card');
  await page.screenshot({ path: `${out}/3-detail.png`, fullPage: true });
  await page.keyboard.press('Escape');
  await page.click('#theme-toggle');
  await page.waitForTimeout(500); // 색 전환(transition) 종료 대기
  await page.screenshot({ path: `${out}/3b-dark.png` });
  await page.click('#theme-toggle');
  await page.click('[data-view=audit]');
  await page.click('#btn-verify');
  await page.waitForFunction(() => document.getElementById('audit-integrity').textContent.includes('무결성 정상'));
  await page.screenshot({ path: `${out}/4-audit.png` });
  console.log('js errors:', JSON.stringify(errors));
  await browser.close();
  if (errors.length) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
