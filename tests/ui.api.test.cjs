const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const bcrypt = require('bcrypt');

test('branded forms save and reload through the authenticated API and real SQLite', { timeout: 30000 }, async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lch-ui-api-'));
  const reservation = net.createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const caddy = path.join(dir, 'caddy');
  await fs.writeFile(caddy, `#!${process.execPath}\nif(process.argv[2]==='environ') console.log('caddy.AppDataDir='+process.env.LCH_DATA_DIR+'/caddy');\n`, { mode: 0o700 });
  const child = spawn(process.execPath, [path.resolve(__dirname, '../src/index.js')], {
    env: { ...process.env, PORT: String(port), LCH_DATA_DIR: dir, CADDY_BIN: caddy, CADDY_AUTOSTART: '0',
      ADMIN_USER: 'bootstrap', ADMIN_PASS: 'bootstrap-password' }, stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  let browser;
  t.after(async () => {
    await browser?.close();
    child.kill('SIGTERM');
    if (child.exitCode === null && child.signalCode === null) await new Promise(resolve => child.once('exit', resolve));
    await fs.rm(dir, { recursive: true, force: true });
  });
  const origin = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(output);
    try { ready = (await fetch(`${origin}/login.html`)).ok; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.ok(ready, output);
  browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.fill('#username', 'bootstrap');
  await page.fill('#password', 'bootstrap-password');
  await page.click('#loginSubmitBtn');
  await page.waitForURL('**/setup.html');
  await page.fill('#newUsername', 'operator');
  await page.fill('#newPassword', 'a-new-secure-password');
  await page.fill('#confirmPassword', 'a-new-secure-password');
  await page.click('#setupSubmitBtn');
  await page.waitForURL(origin + '/');
  await page.waitForFunction(() => window.app?.configLoaded && document.querySelector('#domainModal'));
  await page.selectOption('#languageSelect', 'en');
  const saveModal = async name => {
    await page.click(`#${name} .modal-footer button`);
    await page.waitForSelector(`#${name}`, { state: 'hidden' });
    await page.waitForSelector('.modal-backdrop', { state: 'detached' });
  };
  const openModal = async name => {
    await page.evaluate(name => app.ui.openModal(name), name);
    await page.waitForSelector(`#${name}.show`);
  };
  await openModal('domainModal');
  await page.fill('#d_fd', 'mail.example.test');
  await page.fill('#d_ah', 'autodiscover.example.test, webmail.example.test');
  await saveModal('domainModal');
  await openModal('subdomainModal');
  await page.fill('#sd_fd', 'archive');
  await page.selectOption('#sd_rev', { label: 'mail.example.test' });
  await saveModal('subdomainModal');
  await openModal('accessListModal');
  await page.fill('#al_name', 'Management');
  await page.fill('#al_ips', '10.0.0.0/8, 192.0.2.0/24');
  await saveModal('accessListModal');
  await openModal('basicAuthModal');
  await page.fill('#ba_user', 'service');
  await page.fill('#ba_pass', bcrypt.hashSync('service-password', 4));
  await saveModal('basicAuthModal');
  await openModal('headerModal');
  await page.fill('#hd_name', 'Host');
  await page.fill('#hd_val', '{http.request.host}');
  await saveModal('headerModal');
  await openModal('handlerModal');
  await page.selectOption('#h_rev', { label: 'mail.example.test' });
  await page.fill('#h_hp', '/EWS*');
  await page.check('#h_waf');
  await page.selectOption('#h_waf_profile', 'exchange');
  await page.fill('#h_waf_body_limit', '128');
  await page.click('#h-upstream-tab');
  await page.fill('#h_td', 'exchange01.internal, exchange02.internal');
  await page.fill('#h_tp', '443');
  await page.check('#h_ntlm');
  await saveModal('handlerModal');
  await openModal('layer4Modal');
  await page.fill('#l4_fp', '2525');
  await page.fill('#l4_td', 'exchange01.internal, exchange02.internal');
  await page.fill('#l4_tp', '25');
  await saveModal('layer4Modal');
  const initialRevision = await page.evaluate(() => app.configRevision);
  const saved = page.waitForResponse(response => response.url().endsWith('/api/config/structured') && response.request().method() === 'POST');
  await page.click('#applyConfigBtn');
  const result = await saved;
  assert.equal(result.status(), 200, result.status() === 200 ? undefined : await result.text());
  assert.equal(result.request().headers()['if-match'], initialRevision);
  await page.reload();
  await page.waitForFunction(() => window.app?.configLoaded && app.config.domains.length === 1);
  const config = await page.evaluate(() => app.config);
  for (const section of ['domains', 'subdomains', 'handlers', 'accessLists', 'basicAuths', 'headers', 'layer4']) assert.equal(config[section].length, 1, section);
  assert.deepEqual(config.domains[0].additionalHosts, ['autodiscover.example.test', 'webmail.example.test']);
  assert.deepEqual(config.accessLists[0].clientIps, ['10.0.0.0/8', '192.0.2.0/24']);
  assert.deepEqual(config.layer4[0].toDomain, ['exchange01.internal', 'exchange02.internal']);
  assert.equal(config.handlers[0].waf_profile, 'exchange');
  assert.equal(config.handlers[0].waf_body_limit_mb, 128);
  assert.equal(config.handlers[0].lb_policy, 'ip_hash');

  const loadedRevision = await page.evaluate(() => app.configRevision);
  const current = await page.request.get(origin + '/api/config/structured');
  assert.equal(current.headers().etag, loadedRevision);
  const otherDraft = await current.json();
  otherDraft.general.log_level = 'ERROR';
  const otherSave = await page.request.post(origin + '/api/config/structured', {
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'If-Match': loadedRevision }, data: otherDraft
  });
  assert.equal(otherSave.status(), 200);
  await page.fill('#genHttpPort', '9088');
  await page.evaluate(() => { app.config.domains[0].description = 'Unsaved local draft'; });
  const rejected = page.waitForResponse(response => response.url().endsWith('/api/config/structured') && response.request().method() === 'POST');
  await page.click('#applyConfigBtn');
  assert.equal((await rejected).status(), 412);
  await page.waitForFunction(() => document.querySelector('#globalStatus').textContent.includes('Configuration changed'), undefined, { timeout: 5000 });
  assert.equal(await page.evaluate(() => app.configRevision), loadedRevision);
  assert.equal(await page.evaluate(() => app.config.domains[0].description), 'Unsaved local draft');
  assert.equal(await page.inputValue('#genHttpPort'), '9088');

  const rawSave = await page.request.post(origin + '/api/config', {
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'If-Match': otherSave.headers().etag },
    data: { content: '# browser raw configuration\n' }
  });
  assert.equal(rawSave.status(), 200);
  await page.reload();
  await page.waitForFunction(() => app.configLoaded && app.configMode === 'raw');
  const rawRevision = await page.evaluate(() => app.configRevision);
  let replacementRequests = 0;
  const countReplacements = request => { if (request.method() === 'POST' && request.url().endsWith('/api/config/structured')) replacementRequests++; };
  page.on('request', countReplacements);
  const cancelDialog = page.waitForEvent('dialog');
  const cancelApply = page.click('#applyConfigBtn');
  const warning = await cancelDialog;
  assert.match(warning.message(), /replace.*raw/i);
  await warning.dismiss();
  await cancelApply;
  assert.equal(replacementRequests, 0);
  assert.equal(await page.evaluate(() => app.configRevision), rawRevision);
  page.off('request', countReplacements);
  const accepted = page.waitForResponse(response => response.url().endsWith('/api/config/structured') && response.request().method() === 'POST');
  page.once('dialog', dialog => dialog.accept());
  await page.click('#applyConfigBtn');
  const replacement = await accepted;
  assert.equal(replacement.status(), 200);
  assert.equal(replacement.request().headers()['if-match'], rawRevision);
  assert.equal(replacement.request().headers()['x-config-mode'], 'structured');
  await page.waitForFunction(revision => app.configMode === 'structured' && app.configRevision !== revision, rawRevision, { timeout: 5000 });
  assert.deepEqual(errors, []);
});
