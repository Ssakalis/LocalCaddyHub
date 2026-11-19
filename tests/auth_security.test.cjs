const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const Database = require('better-sqlite3');
const { generateSync } = require('otplib');

const root = process.env.LCH_APP_ROOT || path.resolve(__dirname, '..');
const password = 'synthetic-long-password';
const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const initialEpoch = 1900000020;

async function until(predicate, message, timeout = 7000) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() >= deadline) assert.fail(message);
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lch-auth-security-'));
  const clock = path.join(directory, 'clock');
  const preload = path.join(directory, 'clock.cjs');
  fs.writeFileSync(clock, String(initialEpoch * 1000));
  fs.writeFileSync(preload, `const fs = require('node:fs'); Date.now = () => Number(fs.readFileSync(${JSON.stringify(clock)}, 'utf8'));
    process.on('message', () => process.send(process.getActiveResourcesInfo()));`);
  const children = [];
  const databases = [];
  t.after(async () => {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        for (const reader of readers(child)) process.kill(Number(reader[0]), 'SIGTERM');
        const exited = once(child, 'exit'); child.kill(); await exited;
      }
    }
    for (const database of databases) database.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  async function launch() {
    const socket = net.createServer();
    await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
    const port = socket.address().port;
    await new Promise(resolve => socket.close(resolve));
    const child = spawn(process.execPath, ['--require', preload, path.join(root, 'src/index.js')], {
      cwd: root, env: { ...process.env, LCH_DATA_DIR: directory, PORT: String(port), CADDY_AUTOSTART: '0',
        ADMIN_USER: 'bootstrap', ADMIN_PASS: password }, stdio: ['ignore', 'pipe', 'pipe', 'ipc']
    });
    children.push(child);
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    const base = `http://127.0.0.1:${port}`;
    for (let attempt = 0; attempt < 100; attempt++) {
      assert.equal(child.exitCode, null, output);
      try {
        if ((await fetch(base + '/login.html')).ok) return { child, base, stop: async () => {
          if (child.exitCode !== null || child.signalCode !== null) return;
          const exited = once(child, 'exit'); child.kill(); await exited;
        } };
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    assert.fail(`Application failed to start: ${output}`);
  }
  const app = await launch();
  const database = new Database(path.join(directory, 'caddyhub.db'));
  databases.push(database);
  const request = (route, body, cookie, base = app.base) => fetch(base + route, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest',
      ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(body)
  });
  const cookieFrom = response => response.headers.get('set-cookie')?.split(';')[0];
  const bootstrap = await request('/login', { username: 'bootstrap', password });
  const setup = await request('/api/setup', { newUsername: 'operator', newPassword: password }, cookieFrom(bootstrap));
  assert.equal(setup.status, 200);
  if (options.totp) database.prepare('UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=1').run(secret);
  return { ...app, directory, database, launch, request, cookieFrom, cookie: cookieFrom(setup),
    setEpoch: epoch => fs.writeFileSync(clock, String(epoch * 1000)),
    login: (token, base) => request('/login', { username: 'operator', password, totp: token }, undefined, base),
    code: (epoch = initialEpoch, selectedSecret = secret) => generateSync({ secret: selectedSecret, epoch }) };
}

test('TOTP login consumes one accepted step atomically across parallel requests and restart', { timeout: 20000 }, async t => {
  const app = await fixture(t, { totp: true });
  const peer = await app.launch();
  const attempts = await Promise.all([app.login(app.code()), app.login(app.code(), peer.base)]);
  assert.deepEqual(attempts.map(response => response.status).sort(), [200, 401]);
  assert.equal(app.database.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 2);
  await app.stop();
  await peer.stop();
  const restarted = await app.launch();
  assert.equal((await app.login(app.code(), restarted.base)).status, 401);
  app.setEpoch(initialEpoch + 30);
  assert.equal((await app.login(app.code(initialEpoch + 30), restarted.base)).status, 200);
});

test('TOTP preserves its zero-offset window and allows a later repeated numeric code', { timeout: 20000 }, async t => {
  const app = await fixture(t, { totp: true });
  app.setEpoch(initialEpoch + 2);
  const previous = app.code(initialEpoch - 30);
  assert.equal((await app.login(previous)).status, 401, 'previous time step is outside the supported window');
  assert.equal((await app.login(app.code(initialEpoch + 30))).status, 401, 'future time step is outside the supported window');
  assert.equal((await app.login(app.code())).status, 200);
  assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, 63333334);
  const seen = new Map();
  let collision;
  for (let step = 1; step < 10000; step++) {
    const epoch = initialEpoch + step * 30;
    const code = app.code(epoch);
    if (seen.has(code)) { collision = [seen.get(code), epoch, code]; break; }
    seen.set(code, epoch);
  }
  assert.ok(collision, 'deterministic synthetic secret supplies a repeated code');
  for (const epoch of collision.slice(0, 2)) {
    app.setEpoch(epoch);
    assert.equal((await app.login(collision[2])).status, 200);
  }
});

test('MFA enable consumes its step, same-secret verification cannot reset it, and changed secrets start fresh', { timeout: 15000 }, async t => {
  const app = await fixture(t);
  const enabled = await app.request('/api/2fa/verify', { secret, token: app.code() }, app.cookie);
  assert.equal(enabled.status, 200);
  const enabledCookie = app.cookieFrom(enabled);
  assert.equal((await app.login(app.code())).status, 401, 'enable verification consumes its step');
  assert.equal((await app.request('/api/2fa/verify', { secret, token: app.code() }, enabledCookie)).status, 400);
  assert.equal((await app.request('/api/2fa/verify', { secret: secret.toLowerCase(), token: app.code() }, enabledCookie)).status, 400,
    'alternate casing of the same Base32 secret cannot reset replay protection');
  assert.equal((await fetch(app.base + '/api/2fa/status', { headers: { Cookie: enabledCookie } })).status, 200);
  const nextSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const changed = await app.request('/api/2fa/verify', { secret: nextSecret, token: app.code(initialEpoch, nextSecret) }, enabledCookie);
  assert.equal(changed.status, 200);
  assert.equal((await app.login(app.code(initialEpoch, nextSecret))).status, 401);
  app.setEpoch(initialEpoch + 30);
  const second = await app.login(app.code(initialEpoch + 30, nextSecret));
  assert.equal(second.status, 200);
  const disabled = await app.request('/api/2fa/disable', {}, app.cookieFrom(changed));
  assert.equal(disabled.status, 200);
  assert.equal((await app.login()).status, 200);
  for (const Cookie of [app.cookieFrom(changed), app.cookieFrom(second)]) {
    assert.equal((await fetch(app.base + '/api/2fa/status', { headers: { Cookie } })).status, 401);
  }
  assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, null);
});

for (const direction of ['unpadded to padded', 'padded to unpadded', 'legacy padded']) {
  test(`MFA replay protection recognizes the same Base32 secret: ${direction}`, { timeout: 15000 }, async t => {
    const app = await fixture(t);
    const unpadded = 'JBSWY3DPEHPK3PXPJBSWY3DPEE';
    const padded = unpadded + '======';
    const token = app.code(initialEpoch, unpadded);
    let cookie = app.cookie;
    let replacement;
    if (direction === 'legacy padded') {
      app.database.prepare('UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=1').run(padded.toLowerCase());
      assert.equal((await app.login(token)).status, 200);
      replacement = unpadded;
    } else {
      const first = direction === 'padded to unpadded' ? padded : unpadded;
      const enabled = await app.request('/api/2fa/verify', { secret: first, token }, cookie);
      assert.equal(enabled.status, 200);
      cookie = app.cookieFrom(enabled);
      replacement = direction === 'padded to unpadded' ? unpadded : padded;
    }
    const replay = await app.request('/api/2fa/verify', { secret: replacement, token }, cookie);
    assert.equal(replay.status, 400, 'equivalent padding must not create a new secret version');
    assert.equal(replay.headers.get('set-cookie'), null);
    assert.equal((await app.login(token)).status, 401);
    assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, 63333334);
    app.setEpoch(initialEpoch + 30);
    const malformed = await app.request('/api/2fa/verify', { secret: unpadded + '=======', token: app.code(initialEpoch + 30, unpadded) }, cookie);
    assert.equal(malformed.status, 400, 'canonicalization must not accept malformed Base32 padding');
    assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, 63333334);
    const next = await app.request('/api/2fa/verify', { secret: replacement, token: app.code(initialEpoch + 30, unpadded) }, cookie);
    assert.equal(next.status, 200);
    assert.equal(app.database.prepare('SELECT totp_secret FROM users').get().totp_secret, unpadded);
  });
}

test('TOTP migration preserves an existing account and consumes its first accepted step after upgrade', { timeout: 15000 }, async t => {
  const app = await fixture(t, { totp: true });
  await app.stop();
  app.database.exec('ALTER TABLE users DROP COLUMN totp_last_step');
  const upgraded = await app.launch();
  assert.equal((await app.login(app.code(), upgraded.base)).status, 200);
  assert.equal((await app.login(app.code(), upgraded.base)).status, 401);
  assert.equal(app.database.prepare('SELECT username, totp_last_step FROM users').get().username, 'operator');
  assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, 63333334);
});

test('a failed session insert rolls back TOTP consumption and enrollment', { timeout: 15000 }, async t => {
  const app = await fixture(t, { totp: true });
  app.database.exec("CREATE TRIGGER reject_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'synthetic session failure'); END");
  assert.equal((await app.login(app.code())).status, 500);
  assert.equal(app.database.prepare('SELECT totp_last_step FROM users').get().totp_last_step, null);
  const changedSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal((await app.request('/api/2fa/verify', { secret: changedSecret, token: app.code(initialEpoch, changedSecret) }, app.cookie)).status, 500);
  assert.equal(app.database.prepare('SELECT totp_secret FROM users').get().totp_secret, secret);
  app.database.exec('DROP TRIGGER reject_session');
  assert.equal((await app.login(app.code())).status, 200);
});

async function openStream(app, t, cookie = app.cookie) {
  const response = await new Promise((resolve, reject) => {
    const request = http.get(app.base + '/api/logs/stream?file=access.log', { headers: { Cookie: cookie } }, resolve);
    request.on('error', reject);
    t.after(() => request.destroy());
  });
  let data = '';
  let ended = false;
  response.on('data', chunk => { data += chunk.toString(); });
  response.on('end', () => { ended = true; });
  response.on('close', () => { ended = true; });
  response.on('error', () => {});
  assert.equal(response.statusCode, 200);
  return { response, data: () => data, ended: () => ended };
}

function readers(child) {
  return execFileSync('ps', ['-axo', 'pid=,ppid=,comm='], { encoding: 'utf8' }).split('\n')
    .map(line => line.trim().split(/\s+/)).filter(row => Number(row[1]) === child.pid && /(^|\/)tail$/.test(row[2] || ''));
}

async function timers(child) {
  const reply = once(child, 'message');
  child.send('resources');
  const [resources] = await reply;
  return resources.filter(resource => resource === 'Timeout').length;
}

test('a missing log keeps the SSE error response and starts no reader', { timeout: 15000 }, async t => {
  const app = await fixture(t);
  const response = await fetch(app.base + '/api/logs/stream?file=missing.log', { headers: { Cookie: app.cookie } });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/event-stream/);
  assert.match(await response.text(), /Log file not found/);
  assert.equal(readers(app.child).length, 0);
});

test('SSE follows rename/create rotation and releases each disconnected log reader', { timeout: 20000 }, async t => {
  const app = await fixture(t);
  const baselineTimers = await timers(app.child);
  const log = path.join(app.directory, 'logs/access.log');
  fs.writeFileSync(log, 'initial-marker\n');
  const stream = await openStream(app, t);
  await until(() => stream.data().includes('initial-marker'), 'initial log line missing');
  fs.renameSync(log, log + '.1');
  fs.writeFileSync(log, 'rotated-marker\n');
  await until(() => stream.data().includes('rotated-marker'), 'replacement log not followed');
  fs.appendFileSync(log, 'appended-marker\n');
  await until(() => stream.data().includes('appended-marker'), 'replacement append not followed');
  stream.response.destroy();
  await until(() => readers(app.child).length === 0, 'log reader leaked after disconnect');
  for (let i = 0; i < 5; i++) {
    const opened = await openStream(app, t);
    await until(() => opened.data().includes('appended-marker'), 'reopened stream did not read file');
    opened.response.destroy();
    await until(() => readers(app.child).length === 0, 'repeated open/close leaked reader');
    assert.equal(await timers(app.child), baselineTimers, 'disconnected stream leaked a session check timer');
  }
});

for (const mutation of ['expiry', 'database revocation', 'logout', 'password change', 'MFA enable', 'MFA disable']) {
  test(`SSE closes on ${mutation} without delivering later log entries`, { timeout: 15000 }, async t => {
    const app = await fixture(t, { totp: mutation === 'MFA disable' });
    const log = path.join(app.directory, 'logs/access.log');
    fs.writeFileSync(log, 'before-revocation\n');
    const stream = await openStream(app, t);
    await until(() => stream.data().includes('before-revocation'), 'stream did not open');
    if (mutation === 'expiry') app.setEpoch(initialEpoch + 86400);
    if (mutation === 'database revocation') app.database.prepare('DELETE FROM sessions').run();
    if (mutation === 'logout') await fetch(app.base + '/logout', { headers: { Cookie: app.cookie }, redirect: 'manual' });
    if (mutation === 'password change') assert.equal((await app.request('/api/setup', { newUsername: 'renamed', newPassword: password }, app.cookie)).status, 200);
    if (mutation === 'MFA enable') assert.equal((await app.request('/api/2fa/verify', { secret, token: app.code() }, app.cookie)).status, 200);
    if (mutation === 'MFA disable') assert.equal((await app.request('/api/2fa/disable', {}, app.cookie)).status, 200);
    fs.appendFileSync(log, 'after-revocation-secret\n');
    await until(stream.ended, `stream survived ${mutation}`, 2000);
    assert.equal(stream.data().includes('after-revocation-secret'), false);
    await until(() => readers(app.child).length === 0, 'revoked stream reader leaked');
  });
}

test('logout closes every stream of that session while another login keeps streaming', { timeout: 15000 }, async t => {
  const app = await fixture(t);
  const log = path.join(app.directory, 'logs/access.log');
  fs.writeFileSync(log, 'shared-reader-marker\n');
  const login = await app.login();
  const first = await openStream(app, t);
  const second = await openStream(app, t);
  const other = await openStream(app, t, app.cookieFrom(login));
  await until(() => [first, second, other].every(stream => stream.data().includes('shared-reader-marker')), 'streams did not open');
  await fetch(app.base + '/logout', { headers: { Cookie: app.cookie }, redirect: 'manual' });
  await until(() => first.ended() && second.ended(), 'logout left a session reader open');
  fs.appendFileSync(log, 'other-session-marker\n');
  await until(() => other.data().includes('other-session-marker'), 'unrelated session lost its reader');
  assert.equal(other.ended(), false);
  other.response.destroy();
  await until(() => readers(app.child).length === 0, 'scoped logout leaked a reader');
});

test('SSE ends when its reader exits and does not leave a dangling response', { timeout: 15000 }, async t => {
  const app = await fixture(t);
  fs.writeFileSync(path.join(app.directory, 'logs/access.log'), 'reader-marker\n');
  const stream = await openStream(app, t);
  await until(() => stream.data().includes('reader-marker'), 'stream did not open');
  const reader = readers(app.child)[0];
  assert.ok(reader);
  process.kill(Number(reader[0]), 'SIGTERM');
  await until(stream.ended, 'SSE response remained open after tail exit', 2000);
});
