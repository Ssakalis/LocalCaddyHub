const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function conflict(reason) {
  const error = new Error(`Cannot prove this certificate file unused in the raw Caddyfile: ${reason}`);
  error.status = 409;
  return error;
}

async function assertRawFileUnused(content, filename, { certDir, caddyfile, execCaddy }) {
  const target = path.resolve(certDir, filename);
  let snapshot;
  try {
    const targetStat = await fs.promises.stat(target);
    const targetReal = await fs.promises.realpath(target);
    const identities = new Map([[target, `${targetStat.dev}:${targetStat.ino}:${targetReal}`]]);
    const imported = new Map();
    const sources = new Set([await fs.promises.realpath(caddyfile)]);
    const snippets = new Set();
    const snippetPaths = new Set();
    const imports = [];

    async function checkReference(value, certificateContext = false) {
      if (path.basename(value) === filename) throw conflict('a file reference still uses it');
      if (certificateContext && /[{}*?\[\]]/.test(value)) throw conflict('certificate paths contain dynamic values or globs');
      if ((!certificateContext && !/[./\\]/.test(value)) || value.includes('\n') || value.includes('\0')) return;
      const candidates = path.isAbsolute(value) ? [value] :
        [path.resolve(certDir, value), path.resolve(path.dirname(caddyfile), value), path.resolve(value)];
      for (const candidate of new Set(candidates)) {
        let stat;
        try { stat = await fs.promises.stat(candidate); }
        catch (error) {
          if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
            if (!identities.has(candidate)) identities.set(candidate, null);
            continue;
          }
          throw error;
        }
        const real = await fs.promises.realpath(candidate);
        const identity = `${stat.dev}:${stat.ino}:${real}`;
        if (identities.has(candidate) && identities.get(candidate) !== identity) throw conflict('a referenced path changed during inspection');
        identities.set(candidate, identity);
        if (stat.dev === targetStat.dev && stat.ino === targetStat.ino) throw conflict('a file alias still references it');
        if (certificateContext && stat.isDirectory()) {
          const relative = path.relative(real, targetReal);
          if (relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))) {
            throw conflict('a certificate directory loader includes it');
          }
        }
      }
    }

    async function inspectSource(text, source) {
      if (text.includes('{$') || text.includes('{env.')) throw conflict('environment expansion can change references');
      // shortcut: complex imports and multiline literals stay protected until a Caddy token API is available.
      if (text.includes('`') || text.includes('<<')) throw conflict('multiline literals cannot be inspected safely');
      for (const line of text.split(/\r?\n/)) {
        const snippet = line.match(/^\s*\(([^(){}\s]+)\)\s*\{/);
        if (snippet) snippets.add(snippet[1]);
        const tokens = [];
        for (const match of line.matchAll(/"(?:\\.|[^"\\])*"|#[^\r\n]*|[^\s#]+/g)) {
          const token = match[0];
          if (token.startsWith('#')) break;
          if (token.startsWith('"')) tokens.push(JSON.parse(token));
          else {
            if (/["\\]/.test(token)) throw conflict('ambiguous quoting or escaping cannot be inspected safely');
            tokens.push(token);
          }
        }
        for (const token of tokens) {
          await checkReference(token);
        }
        const position = tokens.indexOf('import');
        if (position < 0) continue;
        if (position !== 0 || tokens.length !== 2 || /[{}*?\[\]\\]/.test(tokens[1])) {
          throw conflict('import globs, arguments or dynamic paths require manual review');
        }
        imports.push({ name: tokens[1], source });
      }
    }

    await inspectSource(content, caddyfile);
    for (const item of imports) {
      const source = path.resolve(path.dirname(item.source), item.name);
      if (snippets.has(item.name)) {
        try {
          await fs.promises.lstat(source);
          throw conflict('a snippet and disk import share a name');
        } catch (error) {
          if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
        }
        snippetPaths.add(source);
        continue;
      }
      const realSource = await fs.promises.realpath(source);
      if (sources.has(realSource) || imported.size >= 64) throw conflict('recursive, repeated or excessive imports require manual review');
      sources.add(realSource);
      await checkReference(source);
      const text = await fs.promises.readFile(source, 'utf8');
      imported.set(source, text);
      await inspectSource(text, source);
    }

    const assertImportsUnchanged = () => {
      for (const source of snippetPaths) {
        try {
          fs.lstatSync(source);
          throw conflict('a disk import appeared beside a matching snippet');
        } catch (error) {
          if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
        }
      }
      for (const [source, text] of imported) {
        try {
          if (fs.readFileSync(source, 'utf8') !== text) throw conflict('an imported file changed during inspection');
        } catch { throw conflict('an imported file changed during inspection'); }
      }
      for (const [reference, expected] of identities) {
        let current = null;
        try {
          const stat = fs.statSync(reference);
          current = `${stat.dev}:${stat.ino}:${fs.realpathSync(reference)}`;
        } catch (error) {
          if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw conflict('a referenced path cannot be checked');
        }
        if (current !== expected) throw conflict('a referenced path changed during inspection');
      }
    };
    snapshot = path.join(path.dirname(caddyfile), `.raw-references-${crypto.randomUUID()}.caddy`);
    await fs.promises.writeFile(snapshot, content, { mode: 0o600, flag: 'wx' });
    const { stdout } = await execCaddy(['adapt', '--adapter', 'caddyfile', '--config', snapshot]);
    const adapted = JSON.parse(stdout);
    if (!adapted || typeof adapted !== 'object' || Array.isArray(adapted)) throw conflict('adaptation did not return a configuration');
    const loaders = adapted.apps?.tls?.certificates;
    if (loaders && Object.keys(loaders).some(name => !['load_files', 'load_folders', 'load_pem'].includes(name))) {
      throw conflict('an unsupported certificate loader requires manual review');
    }
    async function inspectJSON(value, certificateContext = false) {
      if (typeof value === 'string') await checkReference(value, certificateContext);
      else if (Array.isArray(value)) {
        for (const item of value) await inspectJSON(item, certificateContext);
      } else if (value && typeof value === 'object') {
        for (const [name, item] of Object.entries(value)) {
          await inspectJSON(item, certificateContext || value === loaders || /cert|key|file|path/i.test(name));
        }
      }
    }
    await inspectJSON(adapted);
    assertImportsUnchanged();
    return assertImportsUnchanged;
  } catch (error) {
    if (error.status === 409) throw error;
    throw conflict('the Caddyfile or an import could not be fully inspected');
  } finally {
    if (snapshot) await fs.promises.rm(snapshot, { force: true });
  }
}

module.exports = { assertRawFileUnused };
