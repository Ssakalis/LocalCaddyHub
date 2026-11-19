const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn, execFileSync } = require('node:child_process');
const Database = require('better-sqlite3');

const LIMIT = 2 * 1024 * 1024;
async function start(t, prepare) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lch-config-integrity-'));
  const storage = path.join(dir, 'storage');
  const fake = path.join(dir, 'caddy');
  await fs.writeFile(fake, `#!${process.execPath}\nconst fs=require('fs'); const args=process.argv.slice(2); if(args[0]==='environ') console.log(${JSON.stringify('caddy.AppDataDir=' + storage)}); else if(args[0]==='adapt') console.log('{}');\n`, { mode: 0o700 });
  if (prepare) await prepare(dir, storage);
  const http = require('node:http');
  const adminRequests = [];
  const adminState = { failLoad: false };
  const admin = http.createServer((req, res) => { adminRequests.push(req.url); if (adminState.failLoad && req.url === '/load') res.statusCode = 500; res.end('{}'); });
  await new Promise(resolve => admin.listen(0, '127.0.0.1', resolve));
  const preload = path.join(dir, 'isolate-admin.cjs');
  await fs.writeFile(preload, `const original=global.fetch; global.fetch=(url,options)=>original(String(url).replace('http://localhost:2019', 'http://127.0.0.1:${admin.address().port}'),options);
const fs=require('node:fs'), remove=fs.promises.rm, marker=${JSON.stringify(path.join(dir, 'external-after-install'))};
fs.promises.rm=async(file,options)=>{const result=await remove(file,options); if(String(file).startsWith(${JSON.stringify(path.join(dir, 'Caddyfile') + '.')}) && String(file).endsWith('.tmp')){
if(fs.existsSync(marker)){fs.writeFileSync(${JSON.stringify(path.join(dir, 'Caddyfile'))},fs.readFileSync(marker));fs.unlinkSync(marker);}
const gate=${JSON.stringify(path.join(dir, 'hold-cleanup'))};if(fs.existsSync(gate)){fs.unlinkSync(gate);fs.writeFileSync(${JSON.stringify(path.join(dir, 'cleanup-ready'))},'');while(!fs.existsSync(${JSON.stringify(path.join(dir, 'release-cleanup'))}))await new Promise(resolve=>setTimeout(resolve,10));}
}return result;};`);
  let output = "";
  const net = require("node:net");
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  const running = spawn(process.execPath, ['--require', preload, path.resolve(__dirname, '../src/index.js')], {
    env: { ...process.env, PORT: String(port), LCH_DATA_DIR: dir, CADDY_BIN: fake, CADDY_AUTOSTART: '0', ADMIN_USER: 'test', ADMIN_PASS: 'synthetic-bootstrap-password' }, stdio: ['ignore', 'pipe', 'pipe']
  });
  running.stdout.on('data', data => { output += data; }); running.stderr.on('data', data => { output += data; });
  t.after(async () => { running.kill(); if (running.exitCode === null && running.signalCode === null) await new Promise(resolve => running.once('exit', resolve)); admin.closeAllConnections(); await new Promise(resolve => admin.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 200; i++) {
    if (running.exitCode !== null) throw new Error(output);
    try { if ((await fetch(base + '/login.html')).ok) break; } catch {}
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  const auth = await fetch(base + '/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'test', password: 'synthetic-bootstrap-password' }) });
  assert.equal(auth.status, 200, output);
  const headers = { Cookie: auth.headers.get('set-cookie').split(';')[0], 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
  const get = async (route = '/config/structured') => {
    const res = await fetch(base + '/api' + route, { headers });
    assert.equal(res.status, 200);
    return { data: await res.json(), etag: res.headers.get('etag'), mode: res.headers.get('x-config-mode') };
  };
  const post = (route, body, etag) => fetch(base + '/api' + route, { method: 'POST', headers: { ...headers, ...(etag ? { 'If-Match': etag } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { dir, storage, base, headers, get, post, adminRequests, adminState };
}

function domain(id) { return { id, fromDomain: `${id}.example.test`, enabled: false }; }

async function managedPair(storage) {
  const target = path.join(storage, 'certificates', 'acme.test', 'cert.example.test');
  await fs.mkdir(target, { recursive: true });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj', '/CN=cert.example.test', '-keyout', path.join(target, 'cert.example.test.key'), '-out', path.join(target, 'cert.example.test.crt')], { stdio: 'ignore' });
}

test('two clients cannot overwrite a newer structured configuration; missing preconditions fail', async t => {
  const app = await start(t);
  const a = await app.get(), b = await app.get();
  assert.ok(a.etag && a.etag === b.etag);
  for (const [route, body] of [['/config/structured', a.data], ['/config', { content: '# raw' }], ['/certs/letsencrypt/renew-all-rsa', {}], ['/certs/references/cleanup', {}]]) {
    assert.equal((await app.post(route, body)).status, 428, route);
    assert.deepEqual(await app.get(), a);
  }
  a.data.domains.push(domain('client-a'));
  assert.equal((await app.post('/config/structured', a.data, a.etag)).status, 200);
  const before = await app.get();
  b.data.general.log_level = 'DEBUG';
  assert.equal((await app.post('/config/structured', b.data, b.etag)).status, 412);
  const after = await app.get();
  assert.deepEqual(after, before);
  assert.equal(after.data.domains[0].id, 'client-a');
});

test('raw writes share revisions, external edits are detected, and raw mode rejects generated replacements', async t => {
  const app = await start(t);
  const original = await app.get();
  const raw = '# raw security rules\n:8088 {\n respond "private route" 403\n}\n';
  assert.equal((await app.post('/config', { content: raw }, original.etag)).status, 200);
  assert.equal((await app.post('/config/structured', original.data, original.etag)).status, 412);
  const current = await app.get();
  assert.equal(current.mode, 'raw');
  assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 409);
  await fs.writeFile(path.join(app.dir, 'Caddyfile'), raw + '# external modification\n');
  assert.equal((await app.post('/config', { content: 'replacement' }, current.etag)).status, 412);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), raw + '# external modification\n');
});

test('legacy raw configurations, imports and dynamic references protect private keys; unused files are deletable', async t => {
  const app = await start(t, async dir => { await fs.writeFile(path.join(dir, 'Caddyfile'), ':8088 {\n tls cert.pem protected.key\n}\n'); });
  await fs.writeFile(path.join(app.dir, 'certs', 'protected.key'), 'synthetic key');
  await fs.writeFile(path.join(app.dir, 'certs', 'unused.key'), 'unused synthetic key');
  const remove = name => fetch(app.base + '/api/certs?file=' + name, { method: 'DELETE', headers: app.headers });
  assert.equal((await remove('protected.key')).status, 409);
  assert.equal((await remove('unused.key')).status, 200);
  for (const raw of ['import snippets/*.caddy\n', ':8088 { tls {$CERT_PATH} {$KEY_PATH} }\n']) {
    const state = await app.get();
    assert.equal((await app.post('/config', { content: raw }, state.etag)).status, 200);
    assert.equal((await remove('protected.key')).status, 409);
    assert.equal(await fs.readFile(path.join(app.dir, 'certs', 'protected.key'), 'utf8'), 'synthetic key');
  }
});

test('RSA and reference cleanup reject raw mode before changing file, database or revision', async t => {
  const app = await start(t, async (dir, storage) => {
    const target = path.join(storage, 'certificates', 'acme.test', 'cert.example.test');
    await fs.mkdir(target, { recursive: true });
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj', '/CN=cert.example.test', '-keyout', path.join(target, 'cert.example.test.key'), '-out', path.join(target, 'cert.example.test.crt')], { stdio: 'ignore' });
    await fs.writeFile(path.join(dir, 'Caddyfile'), '# raw\n:8088 { respond "secure" 403 }\n');
  });
  const before = await app.get();
  const raw = await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8');
  for (const route of ['/certs/letsencrypt/renew-all-rsa', '/certs/references/cleanup']) {
    const response = await app.post(route, {}, before.etag);
    assert.equal(response.status, 409, await response.text());
    assert.deepEqual(await app.get(), before);
    assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), raw);
  }
  assert.deepEqual(app.adminRequests, [], 'raw-mode rejection never contacts the runtime');
});

test('certificate config actions advance the shared revision and reject stale clients', async t => {
  const app = await start(t, async (dir, storage) => {
    const target = path.join(storage, 'certificates', 'acme.test', 'cert.example.test');
    await fs.mkdir(target, { recursive: true });
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj', '/CN=cert.example.test', '-keyout', path.join(target, 'cert.example.test.key'), '-out', path.join(target, 'cert.example.test.crt')], { stdio: 'ignore' });
  });
  const current = await app.get();
  current.data.general.tls_key_type = 'p256';
  current.data.domains.push({ ...domain('cert'), customCert: 'missing.pem' });
  assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 200);
  const before = await app.get();
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, before.etag)).status, 200);
  const rsa = await app.get();
  assert.notEqual(rsa.etag, before.etag);
  assert.equal(rsa.data.general.tls_key_type, 'rsa2048');
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 412);
  assert.equal((await app.post('/certs/references/cleanup', {}, before.etag)).status, 412);
  assert.equal((await app.post('/certs/references/cleanup', {}, rsa.etag)).status, 200);
  const cleaned = await app.get();
  assert.notEqual(cleaned.etag, rsa.etag);
  assert.equal(cleaned.data.domains[0].customCert, '');
  assert.deepEqual(app.adminRequests, ['/config/', '/load']);
  app.adminState.failLoad = true;
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, cleaned.etag)).status, 500);
  assert.deepEqual(await app.get(), cleaned, 'a failed runtime reload restores file, model and revision');
});

test('external changes during validation and database commit errors preserve the previous state', async t => {
  const app = await start(t);
  const initial = await app.get();
  initial.data.domains.push(domain('saved'));
  assert.equal((await app.post('/config/structured', initial.data, initial.etag)).status, 200);
  const current = await app.get();
  const original = await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8');
  const database = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => database.close());
  database.exec("CREATE TRIGGER reject_config BEFORE UPDATE ON config_state BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
  current.data.domains.push(domain('rejected'));
  assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 500);
  assert.equal((await app.get()).etag, current.etag);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), original);
  database.exec('DROP TRIGGER reject_config');
  const external = '# externally installed\n:8080 { respond 403 }\n';
  await fs.writeFile(path.join(app.dir, 'caddy'), `#!${process.execPath}\nrequire('fs').writeFileSync(${JSON.stringify(path.join(app.dir, 'Caddyfile'))},${JSON.stringify(external)});\n`);
  assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 412);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), external);
  assert.equal((await app.get()).data.domains.length, 1);
});

test('110 and 1000 handlers survive expanded GET/POST with non-ASCII data', async t => {
  const app = await start(t);
  for (const count of [110, 1000]) {
    const current = await app.get();
    current.data.domains = [domain('large')];
    current.data.handlers = Array.from({ length: count }, (_, i) => ({ id: 'handler_' + i, reverse: 'large', enabled: false, description: 'Überprüfung 日本語 🔐' }));
    assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 200);
    const full = await app.get();
    assert.ok(Buffer.byteLength(JSON.stringify(full.data)) > 100 * 1024);
    assert.equal((await app.post('/config/structured', full.data, full.etag)).status, 200);
    assert.equal((await app.get()).data.handlers.length, count);
  }
});

test('configuration limit counts UTF-8 bytes and refuses canonical expansion without partial writes', async t => {
  const app = await start(t);
  const current = await app.get();
  const base = JSON.stringify({ ...current.data, padding: '' });
  const atLimit = base.slice(0, -2) + 'ü'.repeat(Math.floor((LIMIT - Buffer.byteLength(base)) / 2)) + (Buffer.byteLength(base) % 2 ? 'x' : '') + '"}';
  assert.equal(Buffer.byteLength(atLimit), LIMIT);
  assert.equal((await app.post('/config/structured', atLimit, current.etag)).status, 200);
  const before = await app.get();
  assert.equal((await app.post('/config/structured', atLimit + ' ', before.etag)).status, 413);
  const expanded = { ...before.data, domains: [domain('large')], handlers: Array.from({ length: 3000 }, (_, i) => ({ id: 'h' + i, reverse: 'large' })) };
  assert.ok(Buffer.byteLength(JSON.stringify(expanded)) < LIMIT);
  assert.equal((await app.post('/config/structured', expanded, before.etag)).status, 413);
  assert.deepEqual(await app.get(), before);
  const other = await app.post('/setup', { padding: 'ü'.repeat(60 * 1024) });
  assert.equal(other.status, 413, 'other endpoints retain the 100 KiB limit');
});

test('canonical structured and raw GET representations at exactly 2 MiB can be saved again', async t => {
  const app = await start(t);
  let state = await app.get();
  state.data.domains.push({ ...domain('boundary'), description: '' });
  assert.equal((await app.post('/config/structured', state.data, state.etag)).status, 200);
  state = await app.get();
  const spare = LIMIT - Buffer.byteLength(JSON.stringify(state.data));
  state.data.domains[0].description = 'ü'.repeat(Math.floor(spare / 2)) + 'x'.repeat(spare % 2);
  assert.equal(Buffer.byteLength(JSON.stringify(state.data)), LIMIT);
  assert.equal((await app.post('/config/structured', state.data, state.etag)).status, 200);
  const canonical = await app.get();
  assert.equal(Buffer.byteLength(JSON.stringify(canonical.data)), LIMIT);
  assert.equal((await app.post('/config/structured', canonical.data, canonical.etag)).status, 200);
  state = await app.get('/config');
  const overhead = Buffer.byteLength(JSON.stringify({ content: '' }));
  const raw = { content: 'ü'.repeat(Math.floor((LIMIT - overhead) / 2)) + 'x'.repeat((LIMIT - overhead) % 2) };
  assert.equal((await app.post('/config', raw, state.etag)).status, 200);
  const returned = await app.get('/config');
  assert.equal(Buffer.byteLength(JSON.stringify(returned.data)), LIMIT);
  assert.equal((await app.post('/config', returned.data, returned.etag)).status, 200);
  const before = await app.get('/config');
  assert.equal((await app.post('/config', { content: raw.content + 'ü' }, before.etag)).status, 413);
  assert.deepEqual(await app.get('/config'), before);
});

test('legacy generated configurations are adopted and referenced-file deletion is transactional', async t => {
  const app = await start(t);
  const initial = await app.get();
  initial.data.domains.push({ ...domain('legacy'), customCert: 'selected.pem' });
  assert.equal((await app.post('/config/structured', initial.data, initial.etag)).status, 200);
  const database = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => database.close());
  database.exec('DELETE FROM config_state');
  const legacy = await app.get();
  assert.equal(legacy.mode, 'structured');
  await fs.writeFile(path.join(app.dir, 'certs', 'selected.pem'), 'synthetic certificate');
  const remove = revision => fetch(app.base + '/api/certs?file=selected.pem&removeReferences=1', {
    method: 'DELETE', headers: { ...app.headers, ...(revision ? { 'If-Match': revision } : {}) }
  });
  assert.equal((await remove()).status, 428);
  database.exec("CREATE TRIGGER reject_config BEFORE INSERT ON config_state BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
  assert.equal((await remove(legacy.etag)).status, 500);
  assert.deepEqual(await app.get(), legacy);
  assert.equal(await fs.readFile(path.join(app.dir, 'certs', 'selected.pem'), 'utf8'), 'synthetic certificate');
  database.exec('DROP TRIGGER reject_config');
  assert.equal((await remove(legacy.etag)).status, 200);
  const removed = await app.get();
  assert.notEqual(removed.etag, legacy.etag);
  assert.equal(removed.data.domains[0].customCert, '');
  await assert.rejects(fs.access(path.join(app.dir, 'certs', 'selected.pem')), { code: 'ENOENT' });
  assert.deepEqual(await fs.readdir(path.join(app.dir, 'certs')), []);
});

test('RSA rollback protects external changes made during asynchronous staged-file cleanup', async t => {
  const app = await start(t, (dir, storage) => managedPair(storage));
  const before = await app.get();
  const external = '# external raw security\n:8080 { respond 403 }\n';
  await fs.writeFile(path.join(app.dir, 'external-after-install'), external);
  app.adminState.failLoad = true;
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, before.etag)).status, 412);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), external);
  assert.equal((await app.get()).mode, 'raw');
});

test('RSA rollback restores the exact previous snapshot even if Caddy becomes unavailable', async t => {
  const app = await start(t, (dir, storage) => managedPair(storage));
  const before = await app.get();
  const original = await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8');
  const count = path.join(app.dir, 'validations');
  await fs.writeFile(path.join(app.dir, 'caddy'), `#!${process.execPath}\nconst fs=require('fs'),args=process.argv.slice(2);if(args[0]==='environ')console.log(${JSON.stringify('caddy.AppDataDir=' + app.storage)});if(args[0]==='validate'){const n=Number(fs.existsSync(${JSON.stringify(count)})?fs.readFileSync(${JSON.stringify(count)},'utf8'):0)+1;fs.writeFileSync(${JSON.stringify(count)},String(n));if(n>1)process.exit(1);}\n`);
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, before.etag)).status, 500);
  assert.deepEqual(await app.get(), before);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), original);
  assert.equal(await fs.readFile(count, 'utf8'), '2', 'rollback never calls a broken validator');
});

test('RSA rollback preserves an originally absent Caddyfile', async t => {
  const app = await start(t, (dir, storage) => managedPair(storage));
  await fs.unlink(path.join(app.dir, 'Caddyfile'));
  const before = await app.get();
  app.adminState.failLoad = true;
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, before.etag)).status, 500);
  await assert.rejects(fs.access(path.join(app.dir, 'Caddyfile')), { code: 'ENOENT' });
  assert.deepEqual(await app.get(), before);
});

test('write responses return their installed revision rather than a later external revision', async t => {
  const app = await start(t);
  const before = await app.get();
  const external = '# later external configuration\n:8080 { respond 403 }\n';
  await fs.writeFile(path.join(app.dir, 'external-after-install'), external);
  const saved = await app.post('/config/structured', before.data, before.etag);
  assert.equal(saved.status, 200);
  const current = await app.get();
  assert.notEqual(saved.headers.get('etag'), current.etag);
  assert.equal(saved.headers.get('x-config-mode'), 'structured');
  assert.equal(current.mode, 'raw');
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), external);
});

test('legacy raw files remain readable when old database rows cannot be generated', async t => {
  const app = await start(t);
  const db = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => db.close());
  db.prepare('UPDATE general_config SET enabled=1 WHERE id=1').run();
  db.prepare('INSERT INTO domains(id,enabled,fromDomain,accesslist) VALUES(?,?,?,?)').run('legacy', 1, 'legacy.example.test', '["deleted-acl"]');
  const raw = ':8080 { respond 403 }\n';
  await fs.writeFile(path.join(app.dir, 'Caddyfile'), raw);
  const state = await app.get('/config');
  assert.equal(state.mode, 'raw');
  assert.equal(state.data.content, raw);
});

test('normalized structured certificate paths and inode aliases protect their certificate and key', async t => {
  const app = await start(t);
  const before = await app.get();
  before.data.domains.push({ ...domain('selected'), customCert: './selected.pem' });
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 200);
  for (const name of ['selected.pem', 'selected.key']) {
    await fs.writeFile(path.join(app.dir, 'certs', name), 'synthetic ' + name);
    const response = await fetch(app.base + '/api/certs?file=' + name, { method: 'DELETE', headers: app.headers });
    assert.equal(response.status, 409, name);
  }
  const current = await app.get();
  current.data.domains[0].customCert = 'alias.pem';
  await fs.symlink(path.join(app.dir, 'certs', 'selected.pem'), path.join(app.dir, 'certs', 'alias.pem'));
  await fs.link(path.join(app.dir, 'certs', 'selected.key'), path.join(app.dir, 'certs', 'alias.key'));
  assert.equal((await app.post('/config/structured', current.data, current.etag)).status, 200);
  for (const name of ['selected.pem', 'selected.key']) {
    assert.equal((await fetch(app.base + '/api/certs?file=' + name, { method: 'DELETE', headers: app.headers })).status, 409);
  }
});

test('backslash certificate paths are protected exactly like the generated slash paths', async t => {
  const app = await start(t);
  const before = await app.get();
  before.data.domains.push({ ...domain('selected'), customCert: '.\\selected.pem' });
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 200);
  for (const name of ['selected.pem', 'selected.key']) {
    await fs.writeFile(path.join(app.dir, 'certs', name), 'synthetic ' + name);
    assert.equal((await fetch(app.base + '/api/certs?file=' + name, { method: 'DELETE', headers: app.headers })).status, 409);
  }
});

test('existing nested certificates are not missing and cleanup retains their binding', async t => {
  const app = await start(t);
  const before = await app.get();
  before.data.domains.push({ ...domain('selected'), customCert: 'archive/selected.pem' });
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 200);
  await fs.mkdir(path.join(app.dir, 'certs', 'archive'));
  for (const name of ['selected.pem', 'selected.key']) await fs.writeFile(path.join(app.dir, 'certs', 'archive', name), 'synthetic ' + name);
  const saved = await app.get();
  const missing = await fetch(app.base + '/api/certs/references/missing', { headers: app.headers });
  assert.deepEqual(await missing.json(), []);
  assert.equal((await app.post('/certs/references/cleanup', {}, saved.etag)).status, 200);
  assert.deepEqual(await app.get(), saved);
});

test('failed SQLite commit during RSA rollback retains the installed consistent configuration', async t => {
  const app = await start(t, (dir, storage) => managedPair(storage));
  const initial = await app.get();
  initial.data.general.enabled = true;
  initial.data.general.tls_key_type = 'p256';
  assert.equal((await app.post('/config/structured', initial.data, initial.etag)).status, 200);
  const before = await app.get();
  const db = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => db.close());
  db.exec(`CREATE TABLE rollback_parent(id INTEGER PRIMARY KEY);
    CREATE TABLE rollback_failure(id INTEGER REFERENCES rollback_parent(id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER fail_rollback AFTER UPDATE OF tls_key_type ON general_config WHEN NEW.tls_key_type='p256'
    BEGIN INSERT INTO rollback_failure(id) VALUES(999); END;`);
  app.adminState.failLoad = true;
  assert.equal((await app.post('/certs/letsencrypt/renew-all-rsa', {}, before.etag)).status, 500);
  const after = await app.get();
  assert.equal(after.data.general.tls_key_type, 'rsa2048');
  assert.equal(after.mode, 'structured', 'a failed DB commit cannot leave the file on the older state');
  const { generateCaddyfile } = require('../src/caddy');
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), generateCaddyfile(after.data, path.join(app.dir, 'certs'), path.join(app.dir, 'logs')));
});

test('a failed SQLite config commit restores file, model and revision', async t => {
  const app = await start(t);
  const before = await app.get();
  const original = await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8');
  const db = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => db.close());
  db.exec(`CREATE TABLE config_parent(id INTEGER PRIMARY KEY);
    CREATE TABLE config_failure(id INTEGER REFERENCES config_parent(id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER fail_config AFTER INSERT ON domains BEGIN INSERT INTO config_failure(id) VALUES(999); END;`);
  const replacement = structuredClone(before.data);
  replacement.domains.push(domain('rejected'));
  assert.equal((await app.post('/config/structured', replacement, before.etag)).status, 500);
  assert.deepEqual(await app.get(), before);
  assert.equal(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), original);
});

test('certificate rollback preserves a concurrent successful upload instead of replacing it', async t => {
  const app = await start(t);
  const before = await app.get();
  before.data.domains.push({ ...domain('selected'), customCert: 'selected.pem' });
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 200);
  const saved = await app.get();
  const crypto = require('node:crypto');
  const key = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const oldKey = key(), uploadedKey = key();
  await fs.writeFile(path.join(app.dir, 'certs', 'selected.key'), oldKey, { mode: 0o600 });
  const db = new Database(path.join(app.dir, 'caddyhub.db'));
  t.after(() => db.close());
  db.exec(`CREATE TABLE deletion_parent(id INTEGER PRIMARY KEY);
    CREATE TABLE deletion_failure(id INTEGER REFERENCES deletion_parent(id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER fail_deletion AFTER UPDATE OF customCert ON domains WHEN NEW.customCert=''
    BEGIN INSERT INTO deletion_failure(id) VALUES(999); END;`);
  await fs.writeFile(path.join(app.dir, 'hold-cleanup'), '');
  const pending = fetch(app.base + '/api/certs?file=selected.key&removeReferences=1', {
    method: 'DELETE', headers: { ...app.headers, 'If-Match': saved.etag }
  });
  try {
    const deadline = Date.now() + 3000;
    while (true) {
      try { await fs.access(path.join(app.dir, 'cleanup-ready')); break; } catch {}
      assert.ok(Date.now() < deadline, 'deletion reached its asynchronous cleanup');
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    const form = new FormData();
    form.append('file', new Blob([uploadedKey]), 'selected.key');
    assert.equal((await fetch(app.base + '/api/certs', { method: 'POST', headers: {
      Cookie: app.headers.Cookie, 'X-Requested-With': 'XMLHttpRequest'
    }, body: form })).status, 200);
  } finally { await fs.writeFile(path.join(app.dir, 'release-cleanup'), ''); }
  const response = await pending;
  assert.equal(await fs.readFile(path.join(app.dir, 'certs', 'selected.key'), 'utf8'), uploadedKey);
  assert.equal(response.status, 409);
  const retained = (await fs.readdir(path.join(app.dir, 'certs'))).filter(name => name.startsWith('.deleted-'));
  assert.equal(retained.length, 1);
  assert.equal(await fs.readFile(path.join(app.dir, 'certs', retained[0]), 'utf8'), oldKey);
  assert.deepEqual(await app.get(), saved);
});

test('subdomain certificate choices persist and protect their private key on regeneration', async t => {
  const app = await start(t);
  const before = await app.get();
  before.data.general.enabled = true;
  before.data.domains.push({ ...domain('parent'), enabled: true });
  before.data.subdomains.push({ id: 'sub', reverse: 'parent', fromDomain: 'sub', enabled: true, customCert: 'sub.pem' });
  assert.equal((await app.post('/config/structured', before.data, before.etag)).status, 200);
  const saved = await app.get();
  assert.equal(saved.data.subdomains[0].customCert, 'sub.pem');
  assert.match(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), /sub\.pem/);
  for (const name of ['sub.pem', 'sub.key']) {
    await fs.writeFile(path.join(app.dir, 'certs', name), 'synthetic ' + name);
    assert.equal((await fetch(app.base + '/api/certs?file=' + name, { method: 'DELETE', headers: app.headers })).status, 409);
  }
  assert.equal((await app.post('/config/structured', saved.data, saved.etag)).status, 200);
  assert.match(await fs.readFile(path.join(app.dir, 'Caddyfile'), 'utf8'), /sub\.pem/);
});

test('structured admission rejects generated raw JSON larger than the same roundtrip limit', async t => {
  const app = await start(t);
  const before = await app.get();
  const model = structuredClone(before.data);
  model.general.enabled = true;
  model.domains = Array.from({ length: 500 }, (_, i) => ({ ...domain('site' + i), enabled: true, disableTls: true, accesslist: ['shared'] }));
  model.accessLists = [{ id: 'shared', clientIps: Array(1000).fill('192.0.2.1'), http_response_code: '403' }];
  assert.ok(Buffer.byteLength(JSON.stringify(model)) < LIMIT);
  const { generateCaddyfile } = require('../src/caddy');
  assert.ok(Buffer.byteLength(JSON.stringify({ content: generateCaddyfile(model) })) > LIMIT);
  assert.equal((await app.post('/config/structured', model, before.etag)).status, 413);
  assert.deepEqual(await app.get(), before);
});

test('missing-reference cleanup rejects a certificate dependency restored during validation', async t => {
  const app = await start(t);
  const initial = await app.get();
  initial.data.general.enabled = true;
  initial.data.domains.push({ ...domain('restored'), enabled: true, customCert: 'restored.pem' });
  assert.equal((await app.post('/config/structured', initial.data, initial.etag)).status, 200);
  const before = await app.get();
  const caddyfile = path.join(app.dir, 'Caddyfile');
  const original = await fs.readFile(caddyfile, 'utf8');
  const key = path.join(app.dir, 'certs', 'restored.key');
  await fs.writeFile(path.join(app.dir, 'caddy'), `#!${process.execPath}\nif(process.argv[2]==='validate') require('fs').writeFileSync(${JSON.stringify(key)},'restored synthetic private key');\n`);
  const response = await app.post('/certs/references/cleanup', {}, before.etag);
  assert.equal(response.status, 409, 'a restored selected dependency invalidates the cleanup snapshot');
  assert.deepEqual(await app.get(), before, 'model and revision remain unchanged');
  assert.equal(await fs.readFile(caddyfile, 'utf8'), original);
  assert.equal(await fs.readFile(key, 'utf8'), 'restored synthetic private key');
});

test('referenced-file deletion rejects an inode alias added during validation', async t => {
  const app = await start(t);
  const certs = path.join(app.dir, 'certs');
  for (const name of ['selected.pem', 'selected.key', 'other.pem', 'other.key']) {
    await fs.writeFile(path.join(certs, name), 'synthetic ' + name);
  }
  await fs.symlink(path.join(certs, 'other.pem'), path.join(certs, 'alias.pem'));
  await fs.symlink(path.join(certs, 'other.key'), path.join(certs, 'alias.key'));
  const initial = await app.get();
  initial.data.general.enabled = true;
  initial.data.domains.push({ ...domain('selected'), enabled: true, customCert: 'selected.pem' },
    { ...domain('alias'), enabled: true, customCert: 'alias.pem' });
  assert.equal((await app.post('/config/structured', initial.data, initial.etag)).status, 200);
  const before = await app.get();
  const caddyfile = path.join(app.dir, 'Caddyfile');
  const original = await fs.readFile(caddyfile, 'utf8');
  const alias = path.join(certs, 'alias.pem');
  const selected = path.join(certs, 'selected.pem');
  await fs.writeFile(path.join(app.dir, 'caddy'), `#!${process.execPath}\nif(process.argv[2]==='validate'){const fs=require('fs');fs.unlinkSync(${JSON.stringify(alias)});fs.symlinkSync(${JSON.stringify(selected)},${JSON.stringify(alias)});}\n`);
  const response = await fetch(app.base + '/api/certs?file=selected.pem&removeReferences=1', {
    method: 'DELETE', headers: { ...app.headers, 'If-Match': before.etag }
  });
  assert.equal(response.status, 409, 'the newly dependent alias invalidates the deletion snapshot');
  assert.deepEqual(await app.get(), before, 'model and revision remain unchanged');
  assert.equal(await fs.readFile(caddyfile, 'utf8'), original);
  assert.equal(await fs.readFile(selected, 'utf8'), 'synthetic selected.pem');
  assert.equal(await fs.readFile(path.join(certs, 'selected.key'), 'utf8'), 'synthetic selected.key');
  assert.equal(await fs.realpath(alias), await fs.realpath(selected));
});
