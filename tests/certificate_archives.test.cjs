const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');

const root = path.resolve(__dirname, '..');
const realTar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();

async function until(check) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('Timed out waiting for archive lifecycle');
}

async function archiveApp(t, tarMode = '') {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lch-archive-test-'));
  const data = path.join(directory, 'data');
  const storage = path.join(directory, 'storage');
  const certificates = path.join(storage, 'certificates');
  const pair = path.join(certificates, 'issuer', 'test.example');
  await fs.mkdir(pair, { recursive: true });
  await fs.writeFile(path.join(pair, 'test.example.crt'), 'synthetic certificate\n');
  await fs.writeFile(path.join(pair, 'test.example.key'), 'synthetic private key\n', { mode: 0o600 });
  const caddy = path.join(directory, 'caddy');
  await fs.writeFile(caddy, `#!${process.execPath}\nconsole.log(${JSON.stringify('caddy.AppDataDir=' + storage)});\n`, { mode: 0o700 });
  if (tarMode) {
    // Remove a scanned member before running real tar to reproduce an incomplete backup.
    await fs.writeFile(path.join(directory, 'tar'), `#!${process.execPath}\nconst fs = require('node:fs');
const { spawnSync } = require('node:child_process');
fs.writeFileSync(${JSON.stringify(path.join(directory, 'tar.pid'))}, String(process.pid));
${tarMode === 'read-error' ? `fs.unlinkSync(${JSON.stringify(path.join(pair, 'test.example.key'))});` : ''}
${tarMode === 'symlink' ? `fs.unlinkSync(${JSON.stringify(path.join(pair, 'test.example.key'))}); fs.symlinkSync(${JSON.stringify(path.join(directory, 'absent-private.key'))}, ${JSON.stringify(path.join(pair, 'test.example.key'))});` : ''}
const run = () => { const result = spawnSync(${JSON.stringify(realTar)}, process.argv.slice(2), { stdio: 'inherit' }); process.exit(result.status ?? 1); };
${tarMode === 'hold' ? `const timer = setInterval(() => { if (fs.existsSync(${JSON.stringify(path.join(directory, 'release-tar'))})) { clearInterval(timer); run(); } }, 20);` : 'run();'}
`, { mode: 0o700 });
  }
  const child = spawn(process.execPath, ['-e', `const express = require('express');
const app = express(); app.use('/api', require('./src/api'));
const server = app.listen(0, '127.0.0.1', () => console.log('PORT=' + server.address().port));`], {
    cwd: root,
    env: { ...process.env, LCH_DATA_DIR: data, CADDY_BIN: caddy, CADDY_AUTOSTART: '0',
      XDG_DATA_HOME: path.join(directory, 'xdg-data'), XDG_CONFIG_HOME: path.join(directory, 'xdg-config'),
      PATH: tarMode ? directory + path.delimiter + process.env.PATH : process.env.PATH },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await exited;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  const port = await until(() => {
    assert.equal(child.exitCode, null, output);
    return output.match(/PORT=(\d+)/)?.[1];
  });
  return { directory, data, certificates, pair, url: `http://127.0.0.1:${port}/api/certs/acme/download`,
    workspaces: async () => (await fs.readdir(data)).filter(name => name.startsWith('.certificate-archive-')) };
}

test('ACME archives return complete certificate/key contents and remove private staging files', async t => {
  const app = await archiveApp(t);
  const response = await fetch(app.url);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('content-disposition'), /caddy-acme-certificates\.tar\.gz/);
  const archive = path.join(app.directory, 'download.tar.gz');
  await fs.writeFile(archive, Buffer.from(await response.arrayBuffer()));
  assert.equal(execFileSync(realTar, ['-xOf', archive, './issuer/test.example/test.example.crt'], { encoding: 'utf8' }), 'synthetic certificate\n');
  assert.equal(execFileSync(realTar, ['-xOf', archive, './issuer/test.example/test.example.key'], { encoding: 'utf8' }), 'synthetic private key\n');
  await until(async () => (await app.workspaces()).length === 0);
});

test('a real tar read failure returns an HTTP error without a partial archive', async t => {
  const app = await archiveApp(t, 'read-error');
  const response = await fetch(app.url);
  assert.equal(response.status, 500);
  assert.doesNotMatch(response.headers.get('content-type') || '', /gzip/);
  assert.equal(response.headers.get('content-disposition'), null);
  await response.text();
  await until(async () => (await app.workspaces()).length === 0);
});

test('a private key swapped for a symlink before real tar runs cannot produce a successful archive', async t => {
  const app = await archiveApp(t, 'symlink');
  const response = await fetch(app.url);
  assert.equal(response.status, 500);
  assert.equal(response.headers.get('content-disposition'), null);
  await response.text();
  await until(async () => (await app.workspaces()).length === 0);
});

test('an ACME certificate without its companion key fails instead of exporting an incomplete backup', async t => {
  const app = await archiveApp(t);
  await fs.unlink(path.join(app.pair, 'test.example.key'));
  const response = await fetch(app.url);
  assert.equal(response.status, 500);
  assert.equal(response.headers.get('content-disposition'), null);
  await response.text();
  assert.deepEqual(await app.workspaces(), []);
});

test('an orphan ACME private key fails instead of exporting an incomplete backup', async t => {
  const app = await archiveApp(t);
  await fs.unlink(path.join(app.pair, 'test.example.crt'));
  const response = await fetch(app.url);
  assert.equal(response.status, 500);
  assert.equal(response.headers.get('content-disposition'), null);
  await response.text();
  assert.deepEqual(await app.workspaces(), []);
});

test('ACME archive staging is private and a client abort stops tar and cleans its files', async t => {
  const app = await archiveApp(t, 'hold');
  const request = http.get(app.url);
  request.on('error', () => {});
  t.after(() => request.destroy());
  const pid = await until(async () => {
    try { return Number(await fs.readFile(path.join(app.directory, 'tar.pid'), 'utf8')); }
    catch (err) { if (err.code !== 'ENOENT') throw err; }
  });
  const [workspace] = await app.workspaces();
  assert.ok(workspace, 'archive must be staged before sending a success response');
  const staged = path.join(app.data, workspace);
  assert.equal((await fs.stat(staged)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(path.join(staged, 'certificates.tar.gz'))).mode & 0o777, 0o600);
  request.destroy();
  await until(() => {
    try { process.kill(pid, 0); return false; }
    catch (err) { if (err.code !== 'ESRCH') throw err; return true; }
  });
  await until(async () => (await app.workspaces()).length === 0);
});

test('ACME archives reject symlinked private key material and missing storage', async t => {
  const app = await archiveApp(t);
  const key = path.join(app.pair, 'test.example.key');
  await fs.unlink(key);
  await fs.symlink(path.join(app.directory, 'absent-private.key'), key);
  let response = await fetch(app.url);
  assert.equal(response.status, 500);
  await response.text();
  await fs.rm(app.certificates, { recursive: true });
  response = await fetch(app.url);
  assert.equal(response.status, 404);
  await response.text();
  assert.deepEqual(await app.workspaces(), []);
});
