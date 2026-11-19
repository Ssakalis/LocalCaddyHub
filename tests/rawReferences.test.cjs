const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { assertRawFileUnused } = require('../src/rawReferences');

const execute = promisify(execFile);
const realCaddy = process.env.CADDY_BIN;
const needsCaddy = { skip: !realCaddy && 'Set CADDY_BIN to run real Caddy adaptation checks' };

async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lch-raw-reference-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const certDir = path.join(dir, 'certs');
  await fs.mkdir(certDir);
  await fs.writeFile(path.join(certDir, 'protected.key'), 'synthetic private key');
  await fs.writeFile(path.join(certDir, 'unused.key'), 'unused synthetic key');
  const caddyfile = path.join(dir, 'Caddyfile');
  await fs.writeFile(caddyfile, '# untouched original\n');
  return { dir, certDir, caddyfile, execCaddy: args => execute(realCaddy, args, {
    env: { ...process.env, XDG_DATA_HOME: path.join(dir, 'xdg-data'), XDG_CONFIG_HOME: path.join(dir, 'xdg-config') },
    timeout: 5000, maxBuffer: 2 * 1024 * 1024
  }) };
}

const conflict = error => error.status === 409 && /raw|reference|import|certificate|unused/i.test(error.message);

test('raw environment expansion and unresolved imports retain private keys before adaptation', async t => {
  const options = await fixture(t);
  options.execCaddy = async () => ({ stdout: '{}' });
  for (const content of [
    ':8443 {\n tls {$CERT_PATH} {$KEY_PATH}\n}\n',
    ':8080 {\n respond "{env.PRIVATE_KEY}"\n}\n',
    'import snippets/*.caddy\n',
    'import {env.SNIPPET}\n',
    'import snippet argument\n'
  ]) await assert.rejects(assertRawFileUnused(content, 'protected.key', options), conflict);
  assert.equal(await fs.readFile(path.join(options.certDir, 'protected.key'), 'utf8'), 'synthetic private key');
  assert.deepEqual((await fs.readdir(options.dir)).sort(), ['Caddyfile', 'certs']);
});

test('real adapted file references protect keys while an ordinary unused file remains deletable', needsCaddy, async t => {
  const options = await fixture(t);
  const content = ':8443 {\n tls cert.pem protected.key\n}\n';
  await assert.rejects(assertRawFileUnused(content, 'protected.key', options), conflict);
  await assertRawFileUnused(content, 'unused.key', options);
  assert.equal(await fs.readFile(options.caddyfile, 'utf8'), '# untouched original\n');
  assert.deepEqual((await fs.readdir(options.dir)).sort(), ['Caddyfile', 'certs']);
});

test('static relative imports and snippets are adapted and nested environment sources are rejected', needsCaddy, async t => {
  const options = await fixture(t);
  await fs.mkdir(path.join(options.dir, 'snippets'));
  const imported = path.join(options.dir, 'snippets', 'tls.caddy');
  await fs.writeFile(imported, '(selected_tls) {\n tls cert.pem protected.key\n}\n');
  const content = 'import snippets/tls.caddy\n:8443 {\n import selected_tls\n}\n';
  await assert.rejects(assertRawFileUnused(content, 'protected.key', options), conflict);
  await assertRawFileUnused(content, 'unused.key', options);
  await fs.writeFile(imported, '(selected_tls) {\n tls {$CERT_FILE} {$PRIVATE_KEY}\n}\n');
  await assert.rejects(assertRawFileUnused(content, 'unused.key', options), conflict);
});

test('real adapted references recognize symlink and hard-link aliases of private keys', needsCaddy, async t => {
  const options = await fixture(t);
  const target = path.join(options.certDir, 'protected.key');
  for (const link of ['symlink', 'hardlink']) {
    const alias = path.join(options.dir, `${link}.key`);
    if (link === 'symlink') await fs.symlink(target, alias);
    else await fs.link(target, alias);
    await assert.rejects(assertRawFileUnused(`:8443 {\n tls cert.pem "${alias}"\n}\n`, 'protected.key', options), conflict);
  }
});

test('real adapted bare directory names and extensionless key aliases protect uploaded keys', needsCaddy, async t => {
  const options = await fixture(t);
  await fs.symlink(path.join(options.certDir, 'protected.key'), path.join(options.dir, 'secret'));
  await assert.rejects(assertRawFileUnused(':8443 {\n tls cert.pem secret\n}\n', 'protected.key', options), conflict);
  await assert.rejects(assertRawFileUnused(':8443 {\n tls {\n load certs\n }\n}\n', 'protected.key', options), conflict);
});

test('directory certificate loaders and dynamic key paths cannot prove a private key unused', needsCaddy, async t => {
  const options = await fixture(t);
  const content = `:8443 {\n tls {\n load "${options.certDir}"\n }\n}\n`;
  await assert.rejects(assertRawFileUnused(content, 'protected.key', options), conflict);
  await assert.rejects(assertRawFileUnused(':8443 {\n tls cert.pem {env.PRIVATE_KEY}\n}\n', 'protected.key', options), conflict);
});

test('adaptation errors retain files and remove the private same-directory snapshot', needsCaddy, async t => {
  const options = await fixture(t);
  const executeCaddy = options.execCaddy;
  options.execCaddy = async args => {
    const snapshot = args[args.indexOf('--config') + 1];
    assert.equal(path.dirname(snapshot), options.dir);
    assert.equal((await fs.stat(snapshot)).mode & 0o777, 0o600);
    return executeCaddy(args);
  };
  await assert.rejects(assertRawFileUnused('this is not a valid Caddyfile {', 'protected.key', options), conflict);
  assert.deepEqual((await fs.readdir(options.dir)).sort(), ['Caddyfile', 'certs']);
});

test('a literal resembling a snippet cannot hide an imported environment reference', needsCaddy, async t => {
  const options = await fixture(t);
  await fs.writeFile(path.join(options.dir, 'tls-snippet'), '(selected_tls) {\n tls {$CERT_FILE:cert.pem} {$PRIVATE_KEY:other.key}\n}\n');
  const content = ':8080 {\n respond "(tls-snippet)"\n}\nimport tls-snippet\n';
  await assert.rejects(assertRawFileUnused(content, 'unused.key', options), conflict);
});

test('changed static imports fail both the post-adaptation check and the returned pre-delete guard', needsCaddy, async t => {
  const options = await fixture(t);
  const imported = path.join(options.dir, 'site.caddy');
  const original = ':8080 {\n respond "safe"\n}\n';
  await fs.writeFile(imported, original);
  const adapt = options.execCaddy;
  options.execCaddy = async args => {
    const result = await adapt(args);
    await fs.writeFile(imported, original + '# changed\n');
    return result;
  };
  await assert.rejects(assertRawFileUnused('import site.caddy\n', 'unused.key', options), conflict);
  await fs.writeFile(imported, original);
  options.execCaddy = adapt;
  const guard = await assertRawFileUnused('import site.caddy\n', 'unused.key', options);
  await fs.writeFile(imported, original + '# changed again\n');
  assert.throws(guard, conflict);
});

test('the pre-delete guard rejects replaced referenced files and changed symlink parents', needsCaddy, async t => {
  const options = await fixture(t);
  const first = path.join(options.dir, 'first');
  const second = path.join(options.dir, 'second');
  await fs.mkdir(first); await fs.mkdir(second);
  await fs.writeFile(path.join(first, 'other.key'), 'other key');
  await fs.writeFile(path.join(second, 'other.key'), 'other key');
  const alias = path.join(options.dir, 'alias');
  await fs.symlink(first, alias);
  const content = `:8443 {\n tls cert.pem "${path.join(alias, 'other.key')}"\n}\n`;
  const guard = await assertRawFileUnused(content, 'unused.key', options);
  await fs.unlink(alias);
  await fs.symlink(second, alias);
  assert.throws(guard, conflict);
});

test('a later snippet cannot hide a same-name imported file containing environment expansion', needsCaddy, async t => {
  const options = await fixture(t);
  await fs.writeFile(path.join(options.dir, 'selected'), ':8081 {\n respond "{$IMPORTED_RESPONSE:ok}"\n}\n');
  const content = 'import selected\n(selected) {\n respond "safe"\n}\n:8080 {\n respond "ok"\n}\n';
  await assert.rejects(assertRawFileUnused(content, 'unused.key', options), conflict);
});

test('the pre-delete guard rejects a disk import appearing beside a matching snippet', needsCaddy, async t => {
  const options = await fixture(t);
  const content = '(selected) {\n respond "safe"\n}\n:8080 {\n import selected\n}\n';
  const guard = await assertRawFileUnused(content, 'unused.key', options);
  await fs.writeFile(path.join(options.dir, 'selected'), ':8081 {\n respond "{$IMPORTED_RESPONSE:ok}"\n}\n');
  assert.throws(guard, conflict);
});
