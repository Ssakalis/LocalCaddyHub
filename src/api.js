const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');
const db = require('./db');
const { parseJSON, isSafeFilename, asyncHandler } = require('./utils');
const { generateCaddyfile } = require('./caddy');
const appPaths = require('./paths');
const { resolveCaddyBinary } = require('./caddyBinary');
const { CONFIG_JSON_LIMIT } = require('./configLimits');

const router = express.Router();

const certDir = appPaths.certsDir;

const upload = multer({ dest: certDir, limits: { fileSize: 10 * 1024 * 1024 } });
const allowedAcmeCaEndpoints = new Set([
  '',
  'https://acme-v02.api.letsencrypt.org/directory',
  'https://acme-staging-v02.api.letsencrypt.org/directory'
]);
const allowedTlsKeyTypes = new Set(['', 'rsa2048', 'rsa4096', 'p256', 'p384', 'ed25519']);

let configWrite = Promise.resolve();
function serializeConfigWrite(operation) {
  const result = configWrite.then(operation);
  configWrite = result.catch(() => {});
  return result;
}
const configHandler = handler => (req, res, next) => serializeConfigWrite(() => handler(req, res, next)).catch(next);

const getConfigStateStmt = db.prepare('SELECT * FROM config_state WHERE id=1');
const saveConfigStateStmt = db.prepare('INSERT INTO config_state(id, mode, file_hash, version) VALUES(1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, file_hash=excluded.file_hash, version=excluded.version');
const deleteConfigStateStmt = db.prepare('DELETE FROM config_state WHERE id=1');
const fingerprint = value => crypto.createHash('sha256').update(value).digest('hex');
function configError(status, message) { const error = new Error(message); error.status = status; return error; }

function configurationState() {
  return db.transaction(() => {
    let content = null;
    try { content = fs.readFileSync(appPaths.caddyfile, 'utf8'); }
    catch (err) { if (err.code !== 'ENOENT') throw err; }
    const model = structuredConfigFromDb();
    const saved = getConfigStateStmt.get();
    const fileHash = fingerprint(JSON.stringify(content));
    const pristineDefault = content === '{\n\thttp_port 80\n\thttps_port 443\n}\n' && !model.general.enabled &&
      ['domains', 'subdomains', 'handlers', 'accessLists', 'basicAuths', 'headers', 'layer4'].every(name => !model[name].length);
    // Only byte-identical generated legacy files can be adopted without an explicit mode choice.
    let generatedMatch = false;
    if (!saved && content !== null && !pristineDefault) {
      try { generatedMatch = content === generateCaddyfile(model, certDir, appPaths.logsDir); }
      catch { /* Invalid legacy rows cannot establish structured ownership. */ }
    }
    const mode = saved ? (saved.file_hash === fileHash ? saved.mode : 'raw') :
      (content === null || pristineDefault || generatedMatch ? 'structured' : 'raw');
    const etag = '"' + fingerprint(JSON.stringify([saved?.version || 0, mode, fileHash, model])) + '"';
    return { content, fileHash, mode, etag, model, saved, tlsKeyType: getGeneralStmt.get()?.tls_key_type, version: saved?.version || 0 };
  })();
}

function configHeaders(res, state = configurationState()) {
  res.setHeader('ETag', state.etag);
  res.setHeader('X-Config-Mode', state.mode);
  res.setHeader('Cache-Control', 'no-store');
  return state;
}

function requireConfigRevision(req) {
  if (!req.headers['if-match']) throw configError(428, 'Read the configuration first and supply its ETag in If-Match');
  const state = configurationState();
  if (req.headers['if-match'] !== state.etag) throw configError(412, 'Configuration changed. Your draft was not saved; reload and reconcile your changes.');
  return state;
}

function requireStructured(state) {
  if (state.mode !== 'structured') throw configError(409, 'The Caddyfile is raw or was changed externally. This action cannot safely regenerate it from the structured model.');
}

function checkConfigSize(value) {
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > CONFIG_JSON_LIMIT) throw configError(413, 'Configuration exceeds the 2 MiB JSON limit, including its expanded GET representation');
}

function caddyfileIdentity() {
  try {
    const stat = fs.lstatSync(appPaths.caddyfile);
    return JSON.stringify([stat.dev, stat.ino, stat.size, stat.mtimeMs, stat.ctimeMs]);
  } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function persistCaddyfile(content, commit = install => install(), expected, mode = 'structured') {
  checkConfigSize({ content });
  const destination = appPaths.caddyfile;
  const staged = `${destination}.${crypto.randomUUID()}.tmp`;
  let previous;
  let installed = false;
  let installedIdentity;
  let installedState;
  try {
    try { previous = await fs.promises.readFile(destination); }
    catch (err) { if (err.code !== 'ENOENT') throw err; }
    await fs.promises.writeFile(staged, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    try {
      await execCaddyPromise(['validate', '--adapter', 'caddyfile', '--config', staged]);
    } catch (err) {
      err.status = err.code === 'ENOENT' ? 503 : 400;
      throw err;
    }
    db.transaction(() => {
      if (expected && configurationState().etag !== expected.etag) throw configError(412, 'Configuration changed during validation; no changes were saved');
      try {
        saveConfigStateStmt.run(mode, fingerprint(JSON.stringify(content)), (expected?.version || 0) + 1);
        commit(() => {
          fs.renameSync(staged, destination);
          installed = true;
          installedIdentity = caddyfileIdentity();
        });
        installedState = configurationState();
      } catch (err) {
        // Restore before releasing SQLite's writer lock so another writer cannot be overwritten.
        if (installed) {
          if (previous === undefined) fs.unlinkSync(destination);
          else {
            fs.writeFileSync(staged, previous, { mode: 0o600 });
            fs.renameSync(staged, destination);
          }
          installed = false;
        }
        throw err;
      }
    }).immediate();
    return installedState;
  } catch (err) {
    if (installed) {
      db.transaction(() => {
        const current = configurationState();
        if (caddyfileIdentity() !== installedIdentity || JSON.stringify(current.saved) !== JSON.stringify(expected.saved) ||
          JSON.stringify(current.model) !== JSON.stringify(expected.model)) return;
        if (previous === undefined) fs.unlinkSync(destination);
        else {
          fs.writeFileSync(staged, previous, { mode: 0o600, flag: 'wx' });
          fs.renameSync(staged, destination);
        }
      }).immediate();
    }
    throw err;
  } finally {
    await fs.promises.rm(staged, { force: true });
  }
}

function restoreTlsConfiguration(previous, installed) {
  const staged = `${appPaths.caddyfile}.${crypto.randomUUID()}.rollback`;
  let restored = false;
  let restoredIdentity;
  try {
    if (previous.content !== null) fs.writeFileSync(staged, previous.content, { mode: 0o600, flag: 'wx' });
    db.transaction(() => {
      if (configurationState().etag !== installed.etag) throw configError(412, 'Configuration changed after installation; the newer configuration was preserved');
      setGeneralTlsKeyTypeStmt.run(previous.tlsKeyType);
      if (previous.saved) saveConfigStateStmt.run(previous.saved.mode, previous.saved.file_hash, previous.saved.version);
      else deleteConfigStateStmt.run();
      if (previous.content === null) fs.unlinkSync(appPaths.caddyfile);
      else fs.renameSync(staged, appPaths.caddyfile);
      restoredIdentity = caddyfileIdentity();
      restored = true;
    }).immediate();
  } catch (error) {
    if (restored) {
      // A failed SQLite COMMIT restores the installed DB; compensate only our corresponding file.
      db.transaction(() => {
        const current = configurationState();
        if (caddyfileIdentity() === restoredIdentity && JSON.stringify(current.saved) === JSON.stringify(installed.saved) &&
          JSON.stringify(current.model) === JSON.stringify(installed.model)) {
          fs.writeFileSync(staged, installed.content, { mode: 0o600, flag: 'wx' });
          fs.renameSync(staged, appPaths.caddyfile);
        }
      }).immediate();
    }
    throw error;
  } finally {
    fs.rmSync(staged, { force: true });
  }
}

function validateConfigShape(input) {
  const invalid = message => { const error = new Error(message); error.status = 400; throw error; };
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid('Configuration must be an object');
  if (!input.general || typeof input.general !== 'object' || Array.isArray(input.general)) invalid('Missing general configuration');
  for (const name of ['domains', 'subdomains', 'handlers', 'accessLists', 'basicAuths', 'headers', 'layer4']) {
    if (!Array.isArray(input[name])) invalid(`${name} must be an array`);
    const ids = new Set();
    for (const row of input[name]) {
      if (!row || typeof row !== 'object' || Array.isArray(row) || typeof row.id !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(row.id)) invalid(`Invalid ${name} entry ID`);
      if (ids.has(row.id)) invalid(`Duplicate ${name} entry ID`);
      ids.add(row.id);
      if (name === 'handlers') {
        if (row.waf_profile && !['generic', 'exchange'].includes(row.waf_profile)) invalid('Invalid WAF profile');
        if (row.waf_body_limit_mb !== undefined && row.waf_body_limit_mb !== null && row.waf_body_limit_mb !== '' && row.waf_body_limit_mb !== 0) {
          const limit = Number(row.waf_body_limit_mb);
          if (!Number.isInteger(limit) || limit < 1 || limit > 1024) invalid('WAF body limit must be an integer between 1 and 1024 MiB');
        }
      }
    }
  }
  const domains = new Set(input.domains.map(row => row.id));
  const subdomains = new Map(input.subdomains.map(row => [row.id, row]));
  const targets = { accesslist: new Map(input.accessLists.map(row => [row.id, row])),
    basicauth: new Map(input.basicAuths.map(row => [row.id, row])),
    header: new Map(input.headers.map(row => [row.id, row])) };
  for (const row of [...input.domains, ...input.subdomains, ...input.handlers]) {
    for (const field of ['accesslist', 'basicauth', 'header', 'health_headers']) {
      if (row[field] === undefined) continue;
      if (!Array.isArray(row[field])) invalid(`${field} must be an array`);
      const target = targets[field === 'health_headers' ? 'header' : field];
      for (const id of row[field]) {
        if (!target.has(id)) invalid(`Unknown ${field} reference: ${id}`);
        if (field === 'accesslist' && (!Array.isArray(target.get(id).clientIps) || !target.get(id).clientIps.length)) invalid('A referenced access list must contain client IPs');
      }
    }
  }
  for (const row of [...input.subdomains, ...input.handlers]) {
    if (!domains.has(row.reverse)) invalid(`Unknown parent domain: ${row.reverse}`);
  }
  for (const row of input.handlers) {
    if (row.subdomain && (!subdomains.has(row.subdomain) || subdomains.get(row.subdomain).reverse !== row.reverse)) invalid('Handler subdomain must belong to its parent domain');
  }
}

function toStringArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  return [];
}

function toHostArray(value) {
  if (Array.isArray(value)) return value.map(v => String(v || '').trim()).filter(Boolean);
  if (typeof value === 'string') {
    return value.split(',').map(v => v.trim()).filter(Boolean);
  }
  return [];
}

function additionalAcmeHosts(value, parentDomain = '') {
  const parent = String(parentDomain || '').trim().toLowerCase();
  const seen = new Set();
  const hosts = [];

  for (let host of toHostArray(value)) {
    host = host.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
    if (!host) continue;
    if (!host.includes('.') && parent) host = `${host}.${parent}`;
    if (seen.has(host)) continue;
    seen.add(host);
    hosts.push(host);
  }

  return hosts;
}

function autoHttpsDisablesAcme(general = {}) {
  return ['off', 'disable_certs'].includes(general.auto_https || '');
}

function normalizeAcmeCa(value) {
  const endpoint = typeof value === 'string' ? value.trim() : '';
  return allowedAcmeCaEndpoints.has(endpoint) ? endpoint : '';
}

function normalizeTlsKeyType(value) {
  const keyType = typeof value === 'string' ? value.trim() : '';
  if (!keyType) return 'rsa2048';
  return allowedTlsKeyTypes.has(keyType) ? keyType : 'rsa2048';
}

function normalizeAcmeConfig(input) {
  const config = {
    ...input,
    general: input.general || {},
    domains: (input.domains || []).map(d => ({ ...d })),
    subdomains: (input.subdomains || []).map(s => ({ ...s })),
    layer4: (input.layer4 || []).map(l => ({ ...l }))
  };
  config.general.acme_ca = normalizeAcmeCa(config.general.acme_ca);
  config.general.tls_key_type = normalizeTlsKeyType(config.general.tls_key_type);
  const acmeDisabled = autoHttpsDisablesAcme(config.general);
  const domainsById = new Map();

  config.domains.forEach(domain => {
    if (acmeDisabled || domain.disableTls) {
      domain.acme = false;
    }
    domainsById.set(domain.id, domain);
  });

  config.subdomains.forEach(subdomain => {
    const parent = domainsById.get(subdomain.reverse);
    if (acmeDisabled || (parent && parent.disableTls)) {
      subdomain.acme = false;
    }
  });

  config.layer4.forEach(route => {
    if (acmeDisabled || (!route.terminateTls && !route.starttls)) {
      route.acme = false;
    }
    if (route.acme) {
      route.customCert = '';
    }
  });

  return config;
}

// /api/config
router.get('/config', configHandler(async (req, res) => {
  try {
    const state = configHeaders(res);
    res.json({ content: state.content || '' });
  } catch (err) {
    res.status(500).send('Failed to read Caddyfile');
  }
}));

router.post('/config', express.json(), (req, res, next) => serializeConfigWrite(async () => {
  try {
    const state = requireConfigRevision(req);
    const { content } = req.body;
    if (typeof content !== 'string') return res.status(400).send('Invalid request body');
    checkConfigSize({ content });
    const installed = await persistCaddyfile(content, undefined, state, 'raw');
    configHeaders(res, installed);
    res.sendStatus(200);
  } catch (err) {
    res.status(err.status || 500).send(err.status === 412 || err.status === 428 ? err.message : err.stderr || err.message || 'Failed to write Caddyfile');
  }
}).catch(next));

// ⚡ Bolt: Cache prepared SQL statements at module level to eliminate parsing overhead on every request
const getGeneralStmt = db.prepare('SELECT * FROM general_config WHERE id = 1');
const getDomainsStmt = db.prepare('SELECT * FROM domains');
const getSubdomainsStmt = db.prepare('SELECT * FROM subdomains');
const getHandlersStmt = db.prepare('SELECT * FROM handlers');
const getAccessListsStmt = db.prepare('SELECT * FROM access_lists');
const getBasicAuthsStmt = db.prepare('SELECT * FROM basic_auths');
const getHeadersStmt = db.prepare('SELECT * FROM headers');
const getLayer4Stmt = db.prepare('SELECT * FROM layer4');

function structuredConfigFromDb() {
  const general = getGeneralStmt.get() || { enabled: 0, enable_layer4: 0, http_port: '80', https_port: '443', log_level: 'INFO', acme_ca: '' };

  const domainsRows = getDomainsStmt.all();
  const subdomainsRows = getSubdomainsStmt.all();
  const handlersRows = getHandlersStmt.all();
  const accessListsRows = getAccessListsStmt.all();
  const basicAuthsRows = getBasicAuthsStmt.all();
  const headersRows = getHeadersStmt.all();
  const layer4Rows = getLayer4Stmt.all();

  return {
    general: {
      enabled: Boolean(general.enabled),
      enable_layer4: Boolean(general.enable_layer4),
      http_port: general.http_port || '',
      https_port: general.https_port || '',
      log_level: general.log_level || '',
      tls_email: general.tls_email || '',
      acme_ca: normalizeAcmeCa(general.acme_ca),
      tls_key_type: normalizeTlsKeyType(general.tls_key_type),
      http_versions: general.http_versions || '',
      timeout_read_body: general.timeout_read_body || '',
      timeout_read_header: general.timeout_read_header || '',
      timeout_write: general.timeout_write || '',
      timeout_idle: general.timeout_idle || '',
      log_credentials: Boolean(general.log_credentials),
      auto_https: general.auto_https || '',
      log_roll_size_mb: general.log_roll_size_mb || 10,
      log_roll_keep: general.log_roll_keep || 7
    },
    domains: domainsRows.map(d => ({
      ...d,
      enabled: Boolean(d.enabled),
      accessLog: Boolean(d.accessLog),
      disableTls: Boolean(d.disableTls),
      acme: Boolean(d.acme),
      additionalHosts: toHostArray(parseJSON(d.additionalHosts)),
      accesslist: parseJSON(d.accesslist),
      basicauth: parseJSON(d.basicauth)
    })),
    subdomains: subdomainsRows.map(s => ({
      ...s,
      enabled: Boolean(s.enabled),
      acme: Boolean(s.acme),
      additionalHosts: toHostArray(parseJSON(s.additionalHosts)),
      accesslist: parseJSON(s.accesslist),
      basicauth: parseJSON(s.basicauth)
    })),
    handlers: handlersRows.map(h => ({
      ...h,
      enabled: Boolean(h.enabled),
      httpTls: Boolean(h.httpTls),
      ntlm: Boolean(h.ntlm),
      health_follow_redirects: Boolean(h.health_follow_redirects),
      health_status: h.health_status || '',
      health_body: h.health_body || '',
      health_passes: h.health_passes || 0,
      health_fails: h.health_fails || 0,
      health_uri: h.health_uri || '',
      health_port: h.health_port || '',
      health_interval: h.health_interval || '',
      health_timeout: h.health_timeout || '',
      health_headers: parseJSON(h.health_headers),
      passive_health_fail_duration: h.passive_health_fail_duration || '',
      passive_health_max_fails: h.passive_health_max_fails || '',
      passive_health_unhealthy_status: h.passive_health_unhealthy_status || '',
      passive_health_unhealthy_latency: h.passive_health_unhealthy_latency || '',
      passive_health_unhealthy_request_count: h.passive_health_unhealthy_request_count || '',
      http_tls_insecure_skip_verify: Boolean(h.http_tls_insecure_skip_verify),
      http_tls_server_name: h.http_tls_server_name || '',
      http_tls_trusted_ca_certs: h.http_tls_trusted_ca_certs || '',
      accesslist: parseJSON(h.accesslist),
      basicauth: parseJSON(h.basicauth),
      header: parseJSON(h.header),
      toDomain: parseJSON(h.toDomain),
      waf_enabled: Boolean(h.waf_enabled),
      waf_profile: h.waf_profile || 'generic',
      waf_body_limit_mb: h.waf_body_limit_mb || ''
    })),
    accessLists: accessListsRows.map(a => ({
      ...a,
      invert: Boolean(a.invert),
      clientIps: parseJSON(a.clientIps)
    })),
    basicAuths: basicAuthsRows,
    headers: headersRows,
    layer4: layer4Rows.map(l => ({
      ...l,
      enabled: Boolean(l.enabled),
      invert_matchers: Boolean(l.invert_matchers),
      terminateTls: Boolean(l.terminateTls),
      starttls: Boolean(l.starttls),
      acme: Boolean(l.acme),
      fromDomain: toStringArray(parseJSON(l.fromDomain)),
      toDomain: toStringArray(parseJSON(l.toDomain)),
      remote_ip: toStringArray(parseJSON(l.remote_ip))
    }))
  };
}

// /api/config/structured
router.get('/config/structured', configHandler((req, res) => {
  try {
    res.json(configHeaders(res).model);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to read config');
  }
}));

const updateGeneralStmt = db.prepare('UPDATE general_config SET enabled=?, enable_layer4=?, http_port=?, https_port=?, log_level=?, tls_email=?, acme_ca=?, tls_key_type=?, http_versions=?, timeout_read_body=?, timeout_read_header=?, timeout_write=?, timeout_idle=?, log_credentials=?, auto_https=?, log_roll_size_mb=?, log_roll_keep=? WHERE id=1');

const deleteDomainsStmt = db.prepare('DELETE FROM domains');
const insertDomainStmt = db.prepare(`
  INSERT INTO domains (id, enabled, fromDomain, additionalHosts, fromPort, accesslist, basicauth, description, accessLog, disableTls, customCert, client_auth_mode, client_auth_trust_pool, acme)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.enabled'),
    json_extract(value, '$.fromDomain'),
    json_extract(value, '$.additionalHosts'),
    json_extract(value, '$.fromPort'),
    json_extract(value, '$.accesslist'),
    json_extract(value, '$.basicauth'),
    json_extract(value, '$.description'),
    json_extract(value, '$.accessLog'),
    json_extract(value, '$.disableTls'),
    json_extract(value, '$.customCert'),
    json_extract(value, '$.client_auth_mode'),
    json_extract(value, '$.client_auth_trust_pool'),
    json_extract(value, '$.acme')
  FROM json_each(?)
`);

const deleteSubdomainsStmt = db.prepare('DELETE FROM subdomains');
const insertSubdomainStmt = db.prepare(`
  INSERT INTO subdomains (id, enabled, reverse, fromDomain, additionalHosts, accesslist, basicauth, description, customCert, client_auth_mode, client_auth_trust_pool, acme)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.enabled'),
    json_extract(value, '$.reverse'),
    json_extract(value, '$.fromDomain'),
    json_extract(value, '$.additionalHosts'),
    json_extract(value, '$.accesslist'),
    json_extract(value, '$.basicauth'),
    json_extract(value, '$.description'),
    json_extract(value, '$.customCert'),
    json_extract(value, '$.client_auth_mode'),
    json_extract(value, '$.client_auth_trust_pool'),
    json_extract(value, '$.acme')
  FROM json_each(?)
`);

const deleteHandlersStmt = db.prepare('DELETE FROM handlers');
const insertHandlerStmt = db.prepare(`
  INSERT INTO handlers (
    id, enabled, reverse, subdomain, handleType, handlePath, accesslist, basicauth, header, handleDirective, toDomain, toPort, httpTls, ntlm, description,
    lb_policy, lb_retries, lb_try_duration, lb_try_interval,
    health_fails, health_passes, health_timeout, health_interval, health_uri, health_port, health_status, health_body, health_follow_redirects, health_headers,
    to_path, http_version, http_keepalive, http_tls_insecure_skip_verify, http_tls_trusted_ca_certs, http_tls_server_name,
    passive_health_fail_duration, passive_health_max_fails, passive_health_unhealthy_status, passive_health_unhealthy_latency, passive_health_unhealthy_request_count, redir_status, waf_enabled, waf_profile, waf_body_limit_mb
  )
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.enabled'),
    json_extract(value, '$.reverse'),
    json_extract(value, '$.subdomain'),
    json_extract(value, '$.handleType'),
    json_extract(value, '$.handlePath'),
    json_extract(value, '$.accesslist'),
    json_extract(value, '$.basicauth'),
    json_extract(value, '$.header'),
    json_extract(value, '$.handleDirective'),
    json_extract(value, '$.toDomain'),
    json_extract(value, '$.toPort'),
    json_extract(value, '$.httpTls'),
    json_extract(value, '$.ntlm'),
    json_extract(value, '$.description'),
    json_extract(value, '$.lb_policy'),
    json_extract(value, '$.lb_retries'),
    json_extract(value, '$.lb_try_duration'),
    json_extract(value, '$.lb_try_interval'),
    json_extract(value, '$.health_fails'),
    json_extract(value, '$.health_passes'),
    json_extract(value, '$.health_timeout'),
    json_extract(value, '$.health_interval'),
    json_extract(value, '$.health_uri'),
    json_extract(value, '$.health_port'),
    json_extract(value, '$.health_status'),
    json_extract(value, '$.health_body'),
    json_extract(value, '$.health_follow_redirects'),
    json_extract(value, '$.health_headers'),
    json_extract(value, '$.to_path'),
    json_extract(value, '$.http_version'),
    json_extract(value, '$.http_keepalive'),
    json_extract(value, '$.http_tls_insecure_skip_verify'),
    json_extract(value, '$.http_tls_trusted_ca_certs'),
    json_extract(value, '$.http_tls_server_name'),
    json_extract(value, '$.passive_health_fail_duration'),
    json_extract(value, '$.passive_health_max_fails'),
    json_extract(value, '$.passive_health_unhealthy_status'),
    json_extract(value, '$.passive_health_unhealthy_latency'),
    json_extract(value, '$.passive_health_unhealthy_request_count'),
    json_extract(value, '$.redir_status'),
    json_extract(value, '$.waf_enabled'),
    json_extract(value, '$.waf_profile'),
    json_extract(value, '$.waf_body_limit_mb')
  FROM json_each(?)
`);

const deleteAccessListsStmt = db.prepare('DELETE FROM access_lists');
const insertAccessListStmt = db.prepare(`
  INSERT INTO access_lists (id, accesslistName, clientIps, invert, description, http_response_code, http_response_message, request_matcher)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.accesslistName'),
    json_extract(value, '$.clientIps'),
    json_extract(value, '$.invert'),
    json_extract(value, '$.description'),
    json_extract(value, '$.http_response_code'),
    json_extract(value, '$.http_response_message'),
    json_extract(value, '$.request_matcher')
  FROM json_each(?)
`);

const deleteBasicAuthsStmt = db.prepare('DELETE FROM basic_auths');
const insertBasicAuthStmt = db.prepare(`
  INSERT INTO basic_auths (id, basicauthuser, basicauthpass, description)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.basicauthuser'),
    json_extract(value, '$.basicauthpass'),
    json_extract(value, '$.description')
  FROM json_each(?)
`);

const deleteHeadersStmt = db.prepare('DELETE FROM headers');
const insertHeaderStmt = db.prepare(`
  INSERT INTO headers (id, headerUpDown, headerType, headerValue, headerReplace, description)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.headerUpDown'),
    json_extract(value, '$.headerType'),
    json_extract(value, '$.headerValue'),
    json_extract(value, '$.headerReplace'),
    json_extract(value, '$.description')
  FROM json_each(?)
`);

const deleteLayer4Stmt = db.prepare('DELETE FROM layer4');
const insertLayer4Stmt = db.prepare(`
  INSERT INTO layer4 (id, enabled, sequence, type, protocol, fromDomain, fromPort, matchers, invert_matchers, toDomain, toPort, terminateTls, proxyProtocol, description, originate_tls, remote_ip, lb_policy, passive_health_fail_duration, passive_health_max_fails, starttls, default_sni, upstream_tls_server_name, acme, customCert)
  SELECT
    json_extract(value, '$.id'),
    json_extract(value, '$.enabled'),
    json_extract(value, '$.sequence'),
    json_extract(value, '$.type'),
    json_extract(value, '$.protocol'),
    json_extract(value, '$.fromDomain'),
    json_extract(value, '$.fromPort'),
    json_extract(value, '$.matchers'),
    json_extract(value, '$.invert_matchers'),
    json_extract(value, '$.toDomain'),
    json_extract(value, '$.toPort'),
    json_extract(value, '$.terminateTls'),
    json_extract(value, '$.proxyProtocol'),
    json_extract(value, '$.description'),
    json_extract(value, '$.originate_tls'),
    json_extract(value, '$.remote_ip'),
    json_extract(value, '$.lb_policy'),
    json_extract(value, '$.passive_health_fail_duration'),
    json_extract(value, '$.passive_health_max_fails'),
    json_extract(value, '$.starttls'),
    json_extract(value, '$.default_sni'),
    json_extract(value, '$.upstream_tls_server_name'),
    json_extract(value, '$.acme'),
    json_extract(value, '$.customCert')
  FROM json_each(?)
`);

const clearDomainCustomCertStmt = db.prepare("UPDATE domains SET customCert='' WHERE id=?");
const clearDomainClientAuthTrustPoolStmt = db.prepare("UPDATE domains SET client_auth_trust_pool='' WHERE id=?");
const clearSubdomainClientAuthTrustPoolStmt = db.prepare("UPDATE subdomains SET client_auth_trust_pool='' WHERE id=?");
const clearSubdomainCustomCertStmt = db.prepare("UPDATE subdomains SET customCert='' WHERE id=?");
const clearHandlerTrustedCaStmt = db.prepare("UPDATE handlers SET http_tls_trusted_ca_certs='' WHERE id=?");
const clearLayer4CustomCertStmt = db.prepare("UPDATE layer4 SET customCert='' WHERE id=?");
const setGeneralTlsKeyTypeStmt = db.prepare('UPDATE general_config SET tls_key_type=? WHERE id=1');

function keyNameForCustomCertificate(filename) {
  return String(filename || '').replace(/\.(pem|crt|cer)$/i, '') + '.key';
}

function certificateFilePath(filename) {
  return path.resolve(path.join(certDir, filename).replace(/\\/g, '/'));
}

function certificateReferenceRows() {
  const references = [];

  function add(file, type, owner, clearKey, companionOf = '') {
    if (!file) return;
    references.push({ file: path.relative(path.resolve(certDir), certificateFilePath(file)), type, owner, clearKey, companionOf });
  }

  for (const domain of getDomainsStmt.all()) {
    const owner = domain.fromDomain || domain.id;
    if (domain.customCert) {
      add(domain.customCert, 'Domain custom certificate', owner, `domain:customCert:${domain.id}`);
      add(keyNameForCustomCertificate(domain.customCert), 'Domain custom certificate key', owner, `domain:customCert:${domain.id}`, domain.customCert);
    }
    add(domain.client_auth_trust_pool, 'Domain client auth trust pool', owner, `domain:client_auth_trust_pool:${domain.id}`);
  }

  for (const subdomain of getSubdomainsStmt.all()) {
    const owner = subdomain.fromDomain || subdomain.id;
    if (subdomain.customCert) {
      add(subdomain.customCert, 'Subdomain custom certificate', owner, `subdomain:customCert:${subdomain.id}`);
      add(keyNameForCustomCertificate(subdomain.customCert), 'Subdomain custom certificate key', owner, `subdomain:customCert:${subdomain.id}`, subdomain.customCert);
    }
    add(subdomain.client_auth_trust_pool, 'Subdomain client auth trust pool', owner, `subdomain:client_auth_trust_pool:${subdomain.id}`);
  }

  for (const handler of getHandlersStmt.all()) {
    const owner = handler.description || handler.handlePath || handler.id;
    add(handler.http_tls_trusted_ca_certs, 'Handler upstream TLS trusted CA', owner, `handler:http_tls_trusted_ca_certs:${handler.id}`);
  }

  for (const route of getLayer4Stmt.all()) {
    const owner = route.description || route.fromPort || route.id;
    if (route.customCert) {
      add(route.customCert, 'Layer 4 custom certificate', owner, `layer4:customCert:${route.id}`);
      add(keyNameForCustomCertificate(route.customCert), 'Layer 4 custom certificate key', owner, `layer4:customCert:${route.id}`, route.customCert);
    }
  }

  return references;
}

function certificateReferencesForFiles(filenames) {
  const paths = filenames.map(certificateFilePath);
  const stat = file => {
    try { return fs.statSync(file); }
    catch (error) { if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null; throw error; }
  };
  const targets = paths.map(stat);
  return certificateReferenceRows().filter(reference => {
    const file = certificateFilePath(reference.file);
    if (paths.includes(file)) return true;
    const source = stat(file);
    return source && targets.some(target => target && target.dev === source.dev && target.ino === source.ino);
  });
}

function clearCertificateReference(clearKey) {
  const [table, field, id] = String(clearKey).split(':');
  if (!table || !field || !id) return false;

  if (table === 'domain' && field === 'customCert') clearDomainCustomCertStmt.run(id);
  else if (table === 'domain' && field === 'client_auth_trust_pool') clearDomainClientAuthTrustPoolStmt.run(id);
  else if (table === 'subdomain' && field === 'client_auth_trust_pool') clearSubdomainClientAuthTrustPoolStmt.run(id);
  else if (table === 'subdomain' && field === 'customCert') clearSubdomainCustomCertStmt.run(id);
  else if (table === 'handler' && field === 'http_tls_trusted_ca_certs') clearHandlerTrustedCaStmt.run(id);
  else if (table === 'layer4' && field === 'customCert') clearLayer4CustomCertStmt.run(id);
  else return false;

  return true;
}

async function clearCertificateReferencesForFiles(filenames, state, removeFile = () => {}, missingOnly = false) {
  requireStructured(state);
  const files = new Set(filenames.filter(Boolean));
  const cleared = [];
  const seen = new Set();
  const config = structuredConfigFromDb();
  const sections = { domain: 'domains', subdomain: 'subdomains', handler: 'handlers', layer4: 'layer4' };
  for (const reference of certificateReferencesForFiles([...files])) {
    if (seen.has(reference.clearKey)) continue;
    const [type, field, id] = reference.clearKey.split(':');
    const row = config[sections[type]].find(row => row.id === id);
    if (!row) continue;
    row[field] = '';
    seen.add(reference.clearKey);
    cleared.push(reference);
  }
  const recheckReferences = () => {
    const current = new Set(certificateReferencesForFiles([...files]).map(reference => reference.clearKey));
    if (current.size !== seen.size || [...current].some(key => !seen.has(key))) {
      throw configError(409, 'Certificate dependencies changed during validation; no references were removed');
    }
    if (missingOnly) {
      const missing = new Set(missingCertificateReferences().map(reference => certificateFilePath(reference.file)));
      if ([...files].some(file => !missing.has(certificateFilePath(file)))) {
        throw configError(409, 'A missing certificate dependency was restored during validation; no references were removed');
      }
    }
  };
  if (cleared.length) {
    const tx = db.transaction(install => {
      recheckReferences();
      for (const reference of cleared) clearCertificateReference(reference.clearKey);
      removeFile();
      install();
    });
    const installed = await persistCaddyfile(generateCaddyfile(config, certDir, appPaths.logsDir), tx, state);
    return { cleared, state: installed };
  } else {
    db.transaction(() => {
      if (configurationState().etag !== state.etag) throw configError(412, 'Configuration changed; no references were removed');
      recheckReferences();
      removeFile();
    }).immediate();
  }
  return { cleared, state };
}

async function setTlsKeyType(keyType, state) {
  requireStructured(state);
  const config = structuredConfigFromDb();
  config.general.tls_key_type = keyType;
  const tx = db.transaction(install => {
    setGeneralTlsKeyTypeStmt.run(keyType);
    install();
  });
  return persistCaddyfile(generateCaddyfile(config, certDir, appPaths.logsDir), tx, state);
}

function missingCertificateReferences() {
  return certificateReferenceRows().filter(reference => {
    try { return !fs.statSync(certificateFilePath(reference.file)).isFile(); }
    catch (error) { if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return true; throw error; }
  });
}

router.post('/config/structured', express.json(), (req, res, next) => serializeConfigWrite(async () => {
  try {
    const state = requireConfigRevision(req);
    if (req.headers['x-config-mode'] !== 'structured') requireStructured(state);
    validateConfigShape(req.body);
    const config = normalizeAcmeConfig(req.body || {});

    // ⚡ Bolt: Pre-process data outside transaction to minimize write-lock duration.
    const processedDomains = (config.domains || []).map(d => ({
      ...d,
      enabled: d.enabled ? 1 : 0,
      accesslist: JSON.stringify(d.accesslist || []),
      basicauth: JSON.stringify(d.basicauth || []),
      additionalHosts: JSON.stringify(toHostArray(d.additionalHosts)),
      accessLog: d.accessLog ? 1 : 0,
      disableTls: d.disableTls ? 1 : 0,
      acme: d.acme ? 1 : 0
    }));

    const processedSubdomains = (config.subdomains || []).map(s => ({
      ...s,
      enabled: s.enabled ? 1 : 0,
      accesslist: JSON.stringify(s.accesslist || []),
      basicauth: JSON.stringify(s.basicauth || []),
      additionalHosts: JSON.stringify(toHostArray(s.additionalHosts)),
      acme: s.acme ? 1 : 0
    }));

    const processedHandlers = (config.handlers || []).map(h => ({
      ...h,
      lb_policy: h.ntlm && Array.isArray(h.toDomain) && h.toDomain.length > 1 ? 'ip_hash' : h.lb_policy,
      enabled: h.enabled ? 1 : 0,
      accesslist: JSON.stringify(h.accesslist || []),
      basicauth: JSON.stringify(h.basicauth || []),
      header: JSON.stringify(h.header || []),
      toDomain: JSON.stringify(h.toDomain || []),
      httpTls: h.httpTls ? 1 : 0,
      ntlm: h.ntlm ? 1 : 0,
      health_follow_redirects: h.health_follow_redirects ? 1 : 0,
      health_headers: JSON.stringify(h.health_headers || []),
      http_tls_insecure_skip_verify: h.http_tls_insecure_skip_verify ? 1 : 0,
      redir_status: h.redir_status || '301',
      waf_enabled: h.waf_enabled ? 1 : 0,
      waf_profile: h.waf_profile || 'generic',
      waf_body_limit_mb: h.waf_body_limit_mb ? Number(h.waf_body_limit_mb) : null
    }));

    const processedAccessLists = (config.accessLists || []).map(a => ({
      ...a,
      clientIps: JSON.stringify(a.clientIps || []),
      invert: a.invert ? 1 : 0,
      request_matcher: a.request_matcher || 'client_ip'
    }));

    const processedLayer4 = (config.layer4 || []).map(l => ({
      ...l,
      enabled: l.enabled ? 1 : 0,
      fromDomain: JSON.stringify(toStringArray(l.fromDomain)),
      invert_matchers: l.invert_matchers ? 1 : 0,
      toDomain: JSON.stringify(toStringArray(l.toDomain)),
      terminateTls: l.terminateTls ? 1 : 0,
      remote_ip: JSON.stringify(toStringArray(l.remote_ip)),
      starttls: l.starttls ? 1 : 0,
      acme: l.acme ? 1 : 0
    }));

    // ⚡ Bolt: Perform all database operations within a single transaction for atomicity and I/O efficiency.
    const saveTransaction = db.transaction(install => {
      // General
      if (config.general) {
        const http_versions = Array.isArray(config.general.http_versions) ? config.general.http_versions.join(' ') : (config.general.http_versions || '');
        updateGeneralStmt.run(config.general.enabled ? 1 : 0, config.general.enable_layer4 ? 1 : 0, config.general.http_port, config.general.https_port, config.general.log_level, config.general.tls_email, config.general.acme_ca, config.general.tls_key_type, http_versions, config.general.timeout_read_body, config.general.timeout_read_header, config.general.timeout_write, config.general.timeout_idle, config.general.log_credentials ? 1 : 0, config.general.auto_https, config.general.log_roll_size_mb, config.general.log_roll_keep);
      }

      deleteDomainsStmt.run();
      if (processedDomains.length > 0) insertDomainStmt.run(JSON.stringify(processedDomains));

      deleteSubdomainsStmt.run();
      if (processedSubdomains.length > 0) insertSubdomainStmt.run(JSON.stringify(processedSubdomains));

      deleteHandlersStmt.run();
      if (processedHandlers.length > 0) insertHandlerStmt.run(JSON.stringify(processedHandlers));

      deleteAccessListsStmt.run();
      if (processedAccessLists.length > 0) insertAccessListStmt.run(JSON.stringify(processedAccessLists));

      deleteBasicAuthsStmt.run();
      if (config.basicAuths && config.basicAuths.length > 0) insertBasicAuthStmt.run(JSON.stringify(config.basicAuths));

      deleteHeadersStmt.run();
      if (config.headers && config.headers.length > 0) insertHeaderStmt.run(JSON.stringify(config.headers));

      deleteLayer4Stmt.run();
      if (processedLayer4.length > 0) insertLayer4Stmt.run(JSON.stringify(processedLayer4));
      checkConfigSize(structuredConfigFromDb());
      install();
    });

    const caddyfileContent = generateCaddyfile(config, certDir, appPaths.logsDir);
    const installed = await persistCaddyfile(caddyfileContent, saveTransaction, state);

    configHeaders(res, installed);
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.status(err.status || 500).send(err.stderr || err.message || 'Failed to save config');
  }
}).catch(next));

// Logs
const logsDir = appPaths.logsDir || path.join(__dirname, '..', 'data', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

router.get('/logs/files', async (req, res) => {
  try {
    const files = await fs.promises.readdir(logsDir, { withFileTypes: true });
    const logFiles = files.filter(f => f.isFile() && f.name.endsWith('.log')).map(f => f.name);
    res.json(logFiles);
  } catch (err) {
    if (err.code === 'ENOENT') return res.json([]);
    res.status(500).send('Failed to read logs directory');
  }
});

router.get('/logs/stream', asyncHandler(async (req, res) => {
  const filename = req.query.file;
  if (!isSafeFilename(filename) || !filename.endsWith('.log')) {
    return res.status(400).send('Invalid filename');
  }

  const filePath = path.join(logsDir, filename);
  const { isSessionValid, subscribeSessionRevocation } = require('./auth');
  const token = req.cookies.session;
  let tail;
  let timer;
  let unsubscribe = () => {};
  let stopped = false;
  let buffer = '';
  const close = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    unsubscribe();
    if (tail) {
      tail.stdout.removeListener('data', read);
      tail.kill();
    }
    res.removeListener('close', close);
    res.removeListener('error', close);
    if (!res.destroyed && !res.writableEnded) res.end();
  };
  const authorized = () => {
    try { if (isSessionValid(token)) return true; } catch {}
    close();
    return false;
  };
  const read = data => {
    if (stopped || !authorized()) return;
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
      if (line.trim()) res.write(`data: ${line}\n\n`);
    }
  };
  res.once('close', close);
  res.once('error', close);
  try {
    await fs.promises.access(filePath, fs.constants.F_OK);
  } catch (err) {
    if (!stopped) res.type('text/event-stream').end(`data: ${JSON.stringify({ error: 'Log file not found' })}\n\n`);
    close();
    return;
  }
  if (stopped || !authorized()) return;
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.flushHeaders();
  unsubscribe = subscribeSessionRevocation(token, close);
  // Check quiet streams too, including revocations committed by another app process.
  timer = setInterval(authorized, 250);
  timer.unref();
  tail = spawn('tail', ['-F', '-n', '100', '--', filePath]);
  tail.once('error', () => {
    if (!stopped && authorized()) res.write(`data: ${JSON.stringify({ error: 'Failed to start log reader' })}\n\n`);
    close();
  });
  tail.once('exit', close);
  tail.stdout.on('data', read);
  tail.stderr.resume();
}));

// Exec Caddy commands
function execCaddy(cmdArgs, res) {
  execFile(resolveCaddyBinary(), cmdArgs, (error, stdout, stderr) => {
    res.json({
      output: stdout,
      stderr: stderr,
      error: error ? error.message : undefined
    });
  });
}

function execCaddyPromise(cmdArgs) {
  return new Promise((resolve, reject) => {
    execFile(resolveCaddyBinary(), cmdArgs, { timeout: 30000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function isCaddyAdminReady() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);
  try {
    const apiRes = await fetch('http://localhost:2019/config/', {
      headers: { 'Origin': 'http://localhost:2019' },
      signal: controller.signal
    });
    return apiRes.ok;
  } catch (e) {
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function loadCaddyfileThroughAdmin() {
  const caddyfileContent = await fs.promises.readFile(appPaths.caddyfile, 'utf-8');
  const apiRes = await fetch('http://localhost:2019/load', {
    method: 'POST',
    headers: {
      'Content-Type': 'text/caddyfile',
      'Cache-Control': 'no-cache',
      'Origin': 'http://localhost:2019'
    },
    body: caddyfileContent,
    signal: AbortSignal.timeout(10000)
  });
  if (!apiRes.ok) {
    const errText = await apiRes.text();
    const err = new Error(`Failed to reload: ${apiRes.statusText}`);
    err.stderr = errText;
    throw err;
  }
}

function startCaddyDetached() {
  return new Promise((resolve, reject) => {
    const cp = spawn(resolveCaddyBinary(), ['run', '--config', appPaths.caddyfile], {
      detached: true,
      stdio: 'ignore'
    });

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    cp.unref();
    cp.on('error', (err) => finish(reject, err));
    cp.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        finish(reject, new Error(`Caddy exited with code ${code}`));
      }
    });
    setTimeout(() => finish(resolve), 500);
  });
}

router.post('/validate', (req, res) => execCaddy(['validate', '--config', appPaths.caddyfile], res));

router.post('/start', configHandler(async (req, res) => {
  try {
    if (await isCaddyAdminReady()) return res.json({ output: 'Caddy is already running.', stderr: '' });
    await execCaddyPromise(['validate', '--config', appPaths.caddyfile]);
    await startCaddyDetached();
    await waitForCaddyAdminState(true, 15000);
    res.json({ output: 'Caddy started and its admin API is ready.', stderr: '' });
  } catch (err) {
    res.status(503).json({ output: err.stdout || '', stderr: err.stderr || '', error: err.message });
  }
}));

router.post('/stop', async (req, res) => {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const apiRes = await fetch('http://localhost:2019/stop', {
      method: 'POST',
      headers: { 'Origin': 'http://localhost:2019' },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (apiRes.ok) {
      return res.json({ output: 'Caddy stopped successfully.', stderr: '', error: undefined });
    } else {
      return res.json({ output: '', stderr: '', error: `Failed to stop: ${apiRes.statusText}` });
    }
  } catch (e) {
    // If we cannot connect to API, fallback to CLI
    execCaddy(['stop'], res);
  }
});

router.post('/reload', async (req, res) => {
  try {
    await loadCaddyfileThroughAdmin();
    return res.json({ output: 'Caddy reloaded successfully.', stderr: '', error: undefined });
  } catch (e) {
    // If we cannot connect to API, fallback to CLI
    execCaddy(['reload', '--config', appPaths.caddyfile], res);
  }
});

// Stats
router.get('/stats', (req, res) => {
  fetch('http://localhost:2019/metrics', {
    signal: AbortSignal.timeout(2000),
    headers: {
      'Origin': 'http://localhost:2019'
    }
  })
    .then(r => r.text())
    .then(text => {
      res.set('Content-Type', 'text/plain');
      res.send(text);
    })
    .catch(err => {
      res.status(503).send('Metrics unavailable (is Caddy running?)');
    });
});

// Certs
let cachedAppDataDir = null;

function normalizeAcmeHost(value) {
  let host = String(value || '').trim().toLowerCase();
  if (!host) return '';
  try {
    if (/^https?:\/\//.test(host)) host = new URL(host).hostname;
  } catch (e) {
    return '';
  }
  host = host.replace(/^\*\./, '').replace(/\.$/, '');
  if (!host || host.includes('*') || host.includes(':') || !host.includes('.')) return '';
  return host;
}

function configuredAcmeTargets() {
  const general = getGeneralStmt.get() || {};
  if (autoHttpsDisablesAcme(general)) return [];

  const targets = [];
  const seen = new Set();
  const domains = getDomainsStmt.all();
  const domainsById = new Map(domains.map(domain => [domain.id, domain]));

  function addTarget(host, type) {
    const normalized = normalizeAcmeHost(host);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    targets.push({ host: normalized, type });
  }

  for (const domain of domains) {
    if (domain.enabled && domain.acme && !domain.disableTls) {
      addTarget(domain.fromDomain, 'Domain');
      for (const host of additionalAcmeHosts(parseJSON(domain.additionalHosts), domain.fromDomain)) {
        addTarget(host, 'Domain SAN');
      }
    }
  }

  for (const subdomain of getSubdomainsStmt.all()) {
    const parent = domainsById.get(subdomain.reverse);
    if (!subdomain.enabled || !parent || !parent.enabled || parent.disableTls) continue;
    if (subdomain.acme || parent.acme) {
      addTarget(`${subdomain.fromDomain}.${parent.fromDomain}`, 'Subdomain');
      for (const host of additionalAcmeHosts(parseJSON(subdomain.additionalHosts), parent.fromDomain)) {
        addTarget(host, 'Subdomain SAN');
      }
    }
  }

  for (const route of getLayer4Stmt.all()) {
    if (!route.enabled || !route.acme || (!route.terminateTls && !route.starttls)) continue;
    let hosts = toStringArray(parseJSON(route.fromDomain));
    if (hosts.length === 0 && route.default_sni) hosts = [route.default_sni];
    for (const host of hosts) {
      addTarget(host, 'Layer 4');
    }
  }

  return targets;
}

async function getCaddyAppDataDir() {
  if (cachedAppDataDir) return cachedAppDataDir;
  const { stdout } = await execCaddyPromise(['environ']);
  const match = stdout.match(/caddy\.AppDataDir=(.+)/);
  if (!match) throw new Error('Could not find Caddy AppDataDir');
  cachedAppDataDir = match[1].trim();
  return cachedAppDataDir;
}

async function readRecentTextFile(filePath, maxBytes = 256 * 1024) {
  const handle = await fs.promises.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const start = Math.max(0, stat.size - maxBytes);
    const length = stat.size - start;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    return buffer.toString('utf-8');
  } finally {
    await handle.close();
  }
}

function parseCaddyLogLine(line) {
  try {
    const entry = JSON.parse(line);
    return {
      time: entry.ts ? new Date(entry.ts * 1000).toISOString() : '',
      level: entry.level || '',
      logger: entry.logger || '',
      msg: entry.msg || '',
      error: entry.error || '',
      raw: line
    };
  } catch (e) {
    return { time: '', level: '', logger: '', msg: line, error: '', raw: line };
  }
}

function certificateMetadataHosts(metadata = {}) {
  const hosts = new Set();
  const san = metadata.subjectAltName || '';
  for (const match of san.matchAll(/DNS:([^,\s]+)/g)) {
    hosts.add(match[1].toLowerCase());
  }
  const subject = metadata.subject || '';
  for (const match of subject.matchAll(/(?:^|\n|,\s*)CN=([^,\n]+)/g)) {
    hosts.add(match[1].trim().toLowerCase());
  }
  return hosts;
}

async function readAcmeLogEntries(targetHosts) {
  const logPath = path.join(logsDir, 'caddy-global.log');
  let text = '';
  try {
    text = await readRecentTextFile(logPath);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }

  const terms = ['acme', 'letsencrypt', 'certificate', 'challenge', 'issuer', 'tls.obtain', 'tls.renew', 'tls.cache'];
  const hosts = targetHosts.map(host => host.toLowerCase());
  return text.split('\n')
    .filter(Boolean)
    .filter(line => {
      const lower = line.toLowerCase();
      return terms.some(term => lower.includes(term)) || hosts.some(host => lower.includes(host));
    })
    .slice(-80)
    .map(parseCaddyLogLine);
}

async function findManagedCertificateHosts(certificateHosts) {
  const found = new Set();
  if (certificateHosts.length === 0) return found;

  let certificatesDir;
  try {
    certificatesDir = path.join(await getCaddyAppDataDir(), 'certificates');
  } catch (e) {
    return found;
  }

  async function walk(dir, depth = 0) {
    if (depth > 6) return;
    let entries = [];
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      return;
    }

	  for (const entry of entries) {
	    const entryPath = path.join(dir, entry.name);
	    const lowerPath = entryPath.toLowerCase();
	    if (entry.isDirectory()) {
	      await walk(entryPath, depth + 1);
	    } else if (/\.(crt|pem)$/.test(entry.name.toLowerCase())) {
	      const certificateNames = certificateMetadataHosts(await readCertificateMetadata(entryPath));
	      for (const host of certificateHosts) {
	        const normalizedHost = host.toLowerCase();
	        if (lowerPath.includes(normalizedHost) || certificateNames.has(normalizedHost)) {
	          found.add(host);
	        }
	      }
	    }
	  }
  }

  await walk(certificatesDir);
  return found;
}

function pfxCertificateId(source, certPath, keyPath) {
  return crypto
    .createHash('sha256')
    .update(`${source}\0${certPath}\0${keyPath}`)
    .digest('hex');
}

function safeDownloadName(value, fallback = 'certificate') {
  const name = String(value || fallback).replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
  return name || fallback;
}

function parseCertificateDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function firstCertificateInput(buffer) {
  const text = buffer.toString('utf-8');
  const match = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
  return match ? match[0] : buffer;
}

async function readCertificateMetadata(certPath) {
  try {
    const input = firstCertificateInput(await fs.promises.readFile(certPath));
    const certificate = new crypto.X509Certificate(input);
    const validFrom = parseCertificateDate(certificate.validFrom);
    const validTo = parseCertificateDate(certificate.validTo);
    const daysRemaining = validTo ? Math.ceil((validTo.getTime() - Date.now()) / 86400000) : null;

    return {
      validFrom: validFrom ? validFrom.toISOString() : '',
      validTo: validTo ? validTo.toISOString() : '',
      daysRemaining,
      expired: typeof daysRemaining === 'number' ? daysRemaining < 0 : false,
      expiresSoon: typeof daysRemaining === 'number' ? daysRemaining >= 0 && daysRemaining <= 30 : false,
      subject: certificate.subject || '',
      certificateIssuer: certificate.issuer || '',
      subjectAltName: certificate.subjectAltName || '',
      serialNumber: certificate.serialNumber || '',
      fingerprint256: certificate.fingerprint256 || ''
    };
  } catch (err) {
    return {
      validFrom: '',
      validTo: '',
      daysRemaining: null,
      expired: false,
      expiresSoon: false,
      certificateParseError: err.message
    };
  }
}

function publicCertificateMetadata(certificate) {
  return {
    validFrom: certificate.validFrom || '',
    validTo: certificate.validTo || '',
    daysRemaining: typeof certificate.daysRemaining === 'number' ? certificate.daysRemaining : null,
    expired: Boolean(certificate.expired),
    expiresSoon: Boolean(certificate.expiresSoon),
    subject: certificate.subject || '',
    certificateIssuer: certificate.certificateIssuer || '',
    subjectAltName: certificate.subjectAltName || '',
    serialNumber: certificate.serialNumber || '',
    fingerprint256: certificate.fingerprint256 || '',
    certificateParseError: certificate.certificateParseError || ''
  };
}

async function listCertificatePairs(rootDir, options = {}) {
  const pairs = [];
  const source = options.source || 'Certificate';
  const recursive = Boolean(options.recursive);
  const maxDepth = options.maxDepth || 6;

  async function scan(dir, depth = 0) {
    let entries = [];
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      return;
    }

    const files = entries.filter(entry => entry.isFile()).map(entry => entry.name);
    const keys = new Map(
      files
        .filter(name => name.toLowerCase().endsWith('.key'))
        .map(name => [name.replace(/\.key$/i, '').toLowerCase(), name])
    );
    const certs = files.filter(name => /\.(crt|pem|cer)$/i.test(name));

    for (const certName of certs) {
      const base = certName.replace(/\.(crt|pem|cer)$/i, '');
      const keyName = keys.get(base.toLowerCase());
      if (!keyName) continue;

      const certPath = path.join(dir, certName);
      const keyPath = path.join(dir, keyName);
      const relDir = path.relative(rootDir, dir);
      const relCert = path.relative(rootDir, certPath);
      const relKey = path.relative(rootDir, keyPath);
      const issuer = relDir && relDir !== '.' ? relDir.split(path.sep)[0] : '';
      const host = base.toLowerCase();
      const metadata = await readCertificateMetadata(certPath);

      pairs.push({
        id: pfxCertificateId(source, certPath, keyPath),
        name: base,
        host,
        source,
        issuer,
        certRelPath: relCert,
        keyRelPath: relKey,
        certPath,
        keyPath,
        storageDir: dir,
        renewable: source === 'Caddy-managed ACME',
        ...metadata
      });
    }

    if (!recursive || depth >= maxDepth) return;
    for (const entry of entries) {
      if (entry.isDirectory()) {
        await scan(path.join(dir, entry.name), depth + 1);
      }
    }
  }

  await scan(rootDir);
  return pairs;
}

async function listPfxCertificates() {
  const customPairs = await listCertificatePairs(certDir, { source: 'Custom upload' });
  let managedPairs = [];
  try {
    const certificatesDir = path.join(await getCaddyAppDataDir(), 'certificates');
    managedPairs = await listCertificatePairs(certificatesDir, {
      source: 'Caddy-managed ACME',
      recursive: true
    });
  } catch (e) {
    managedPairs = [];
  }

  const byId = new Map();
  for (const pair of [...managedPairs, ...customPairs]) {
    byId.set(pair.id, pair);
  }

  return [...byId.values()].sort((a, b) => {
    return `${a.source}:${a.name}`.localeCompare(`${b.source}:${b.name}`);
  });
}

function publicPfxCertificate(pair) {
  return {
    id: pair.id,
    name: pair.name,
    host: pair.host,
    source: pair.source,
    issuer: pair.issuer,
    certRelPath: pair.certRelPath,
    renewable: Boolean(pair.renewable),
    ...publicCertificateMetadata(pair)
  };
}

async function listCustomCertificateFiles() {
  const dirents = await fs.promises.readdir(certDir, { withFileTypes: true });
  const files = dirents
    .filter(dirent => !dirent.isDirectory())
    .map(dirent => dirent.name)
    .sort((a, b) => a.localeCompare(b));

  return Promise.all(files.map(async (name) => {
    const lowerName = name.toLowerCase();
    const isCertificate = /\.(crt|pem|cer)$/i.test(name);
    const file = {
      name,
      source: 'Custom upload',
      kind: lowerName.endsWith('.key') ? 'key' : (isCertificate ? 'certificate' : 'file')
    };

    if (isCertificate) {
      Object.assign(file, await readCertificateMetadata(path.join(certDir, name)));
    }

    return file;
  }));
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForCaddyAdminState(expectedReady, timeoutMs = 10000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if ((await isCaddyAdminReady()) === expectedReady) return;
    await sleep(250);
  }
  throw new Error(expectedReady ? 'Caddy admin API did not become reachable' : 'Caddy admin API did not stop');
}

async function reloadOrStartCaddy() {
  await execCaddyPromise(['validate', '--config', appPaths.caddyfile]);
  if (await isCaddyAdminReady()) {
    await loadCaddyfileThroughAdmin();
    return 'Caddy configuration reloaded; established connections and stored certificates were preserved.';
  }
  await startCaddyDetached();
  await waitForCaddyAdminState(true, 15000);
  return 'Caddy started with the existing certificate storage.';
}

router.post('/certs/letsencrypt/request', async (req, res) => {
  try {
    const targets = configuredAcmeTargets();
    if (targets.length === 0) {
      return res.json({
        output: '',
        stderr: '',
        error: 'No valid Let\'s Encrypt targets are configured. Enable Let\'s Encrypt on a public domain first.',
        targets
      });
    }

    await fs.promises.access(appPaths.caddyfile, fs.constants.F_OK);
    await execCaddyPromise(['validate', '--config', appPaths.caddyfile]);

    if (await isCaddyAdminReady()) {
      await loadCaddyfileThroughAdmin();
      return res.json({
        output: 'Caddy reloaded successfully. Let\'s Encrypt certificate issuance has been requested for configured ACME domains.',
        stderr: '',
        error: undefined,
        targets
      });
    }

    await startCaddyDetached();
    res.json({
      output: 'Caddy start command executed. Let\'s Encrypt certificate issuance has been requested for configured ACME domains.',
      stderr: '',
      error: undefined,
      targets
    });
  } catch (err) {
    res.json({
      output: err.stdout || '',
      stderr: err.stderr || '',
      error: err.message
    });
  }
});

router.get('/certs/letsencrypt/status', async (req, res) => {
  try {
    const targets = configuredAcmeTargets();
    const hosts = targets.map(target => target.host);
    const [caddyRunning, foundHosts, logs] = await Promise.all([
      isCaddyAdminReady(),
      findManagedCertificateHosts(hosts),
      readAcmeLogEntries(hosts)
    ]);

    res.json({
      checkedAt: new Date().toISOString(),
      caddyRunning,
      targets: targets.map(target => ({
        ...target,
        certificateFound: foundHosts.has(target.host)
      })),
      logs
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/certs/letsencrypt/renew', express.json(), configHandler(async (req, res) => {
  const { id } = req.body || {};
  if (typeof id !== 'string' || !id) return res.status(400).json({ error: 'Missing certificate selection' });
  try {
    const certificate = (await listPfxCertificates()).find(pair => pair.id === id);
    if (!certificate) return res.status(404).json({ error: 'Certificate/key pair not found' });
    if (!certificate.renewable) return res.status(400).json({ error: 'Only Caddy-managed ACME certificates renew automatically' });
    const output = await reloadOrStartCaddy();
    res.json({ output: `${output} Caddy renews certificates automatically when due; no forced replacement was performed.`,
      stderr: '', certificate: publicPfxCertificate(certificate) });
  } catch (err) {
    res.status(500).json({ output: err.stdout || '', stderr: err.stderr || '', error: err.message });
  }
}));

router.post('/certs/letsencrypt/renew-all-rsa', express.json(), configHandler(async (req, res) => {
  try {
    const state = requireConfigRevision(req);
    requireStructured(state);
    const certificates = (await listPfxCertificates()).filter(pair => pair.renewable);
    if (certificates.length === 0) return res.status(404).json({ error: 'No Caddy-managed ACME certificates found' });
    const installed = await setTlsKeyType('rsa2048', state);
    let output;
    try { output = await reloadOrStartCaddy(); }
    catch (error) {
      restoreTlsConfiguration(state, installed);
      throw error;
    }
    configHeaders(res, installed);
    res.json({ output: `RSA 2048 configured for future issuances and automatic renewals. Existing certificates were preserved. ${output}`,
      stderr: '', certificates: certificates.map(publicPfxCertificate) });
  } catch (err) {
    res.status(err.status || 500).json({ output: err.stdout || '', stderr: err.stderr || '', error: err.message });
  }
}));

router.get('/certs/pfx/list', async (req, res) => {
  try {
    const certificates = await listPfxCertificates();
    res.json(certificates.map(publicPfxCertificate));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/certs/pfx/download', express.json(), asyncHandler(async (req, res) => {
  const { id, password } = req.body || {};
  if (typeof id !== 'string' || !id) {
    return res.status(400).send('Missing certificate selection');
  }
  if (typeof password !== 'string' || password.length < 1 || password.length > 256 || password.includes('\0')) {
    return res.status(400).send('Password must be between 1 and 256 characters');
  }

  const certificate = (await listPfxCertificates()).find(pair => pair.id === id);
  if (!certificate) {
    return res.status(404).send('Certificate/key pair not found');
  }

  const outputName = `${safeDownloadName(certificate.name)}.pfx`;
  const env = {
    ...process.env,
    LOCALCADDYHUB_PFX_PASSWORD: password
  };
  const args = [
    'pkcs12',
    '-export',
    '-inkey', certificate.keyPath,
    '-in', certificate.certPath,
    '-out', '-',
    '-name', certificate.name,
    '-passout', 'env:LOCALCADDYHUB_PFX_PASSWORD'
  ];

  execFile('openssl', args, { encoding: 'buffer', maxBuffer: 20 * 1024 * 1024, env }, (error, stdout, stderr) => {
    if (error) {
      console.error(`PFX export failed: ${stderr ? stderr.toString('utf-8') : error.message}`);
      return res.status(500).send(stderr ? stderr.toString('utf-8') : error.message);
    }

    res.setHeader('Content-Type', 'application/x-pkcs12');
    res.setHeader('Content-Disposition', `attachment; filename="${outputName}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send(stdout);
  });
}));

router.get('/certs/references/missing', async (req, res) => {
  try {
    res.json(await missingCertificateReferences());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/certs/references/cleanup', express.json(), configHandler(async (req, res) => {
  try {
    const state = requireConfigRevision(req);
    requireStructured(state);
    const missing = await missingCertificateReferences();
    const result = await clearCertificateReferencesForFiles(missing.map(reference => reference.file), state, undefined, true);
    configHeaders(res, result.state);
    res.json({ missing, cleared: result.cleared });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
}));

router.get('/certs/acme/download', async (req, res) => {
  try {
    const certificatesDir = path.join(await getCaddyAppDataDir(), 'certificates');
    return await serveCertificates(certificatesDir, res);
  } catch (error) {
    console.error('Failed to query Caddy environment:', error);
    return res.status(500).send(error.message || 'Failed to query Caddy environment');
  }
});

async function serveCertificates(certificatesDir, res) {
  try {
    const directory = await fs.promises.lstat(certificatesDir);
    if (!directory.isDirectory()) throw new Error('Invalid certificate directory');
  } catch (err) {
    return res.status(err.code === 'ENOENT' ? 404 : 500).send('No Caddy-managed ACME certificates found.');
  }

  let workspace;
  let tarProcess;
  const stopArchive = () => tarProcess?.kill();
  res.once('close', stopArchive);
  try {
    const members = [];
    const sourceStates = new Map();
    const fileState = stat => [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeMs, stat.ctimeMs].join(':');
    async function checkPairs(directory) {
      const entries = await fs.promises.readdir(directory, { withFileTypes: true });
      const keys = new Set(entries.filter(entry => entry.isFile() && /\.key$/i.test(entry.name))
        .map(entry => entry.name.replace(/\.key$/i, '').toLowerCase()));
      const certificates = new Set(entries.filter(entry => entry.isFile() && /\.(crt|pem|cer)$/i.test(entry.name))
        .map(entry => entry.name.replace(/\.(crt|pem|cer)$/i, '').toLowerCase()));
      for (const entry of entries) {
        if (res.destroyed) throw new Error('Download closed');
        if (entry.isDirectory()) await checkPairs(path.join(directory, entry.name));
        else if (!entry.isFile()) throw new Error('Certificate storage contains a link or special file');
        else if (/\.(crt|pem|cer)$/i.test(entry.name) && !keys.has(entry.name.replace(/\.(crt|pem|cer)$/i, '').toLowerCase())) {
          throw new Error('Certificate storage is missing a companion private key');
        }
        else if (/\.key$/i.test(entry.name) && !certificates.has(entry.name.replace(/\.key$/i, '').toLowerCase())) {
          throw new Error('Certificate storage is missing a companion certificate');
        }
        else {
          const file = path.join(directory, entry.name);
          const stat = await fs.promises.lstat(file);
          if (!stat.isFile()) throw new Error('Certificate storage changed during inspection');
          sourceStates.set(file, fileState(stat));
          members.push(`./${path.relative(certificatesDir, file)}`);
        }
      }
    }
    await checkPairs(certificatesDir);
    if (res.destroyed) return;
    workspace = await fs.promises.mkdtemp(path.join(path.dirname(appPaths.db), '.certificate-archive-'));
    const archive = path.join(workspace, 'certificates.tar.gz');
    const manifest = path.join(workspace, 'members');
    await fs.promises.writeFile(archive, '', { mode: 0o600, flag: 'wx' });
    // An explicit list makes tar fail if a scanned key disappears before it is read.
    await fs.promises.writeFile(manifest, members.map(member => `${member}\0`).join(''), { mode: 0o600, flag: 'wx' });
    if (res.destroyed) return;
    await new Promise((resolve, reject) => {
      tarProcess = spawn('tar', ['-czf', archive, '-C', certificatesDir, '--null', '-T', manifest], { stdio: 'ignore' });
      tarProcess.once('error', reject);
      tarProcess.once('close', code => code === 0 ? resolve() : reject(new Error(`tar exited with code ${code}`)));
    });
    tarProcess = null;
    if (res.destroyed) return;
    for (const [file, state] of sourceStates) {
      const stat = await fs.promises.lstat(file);
      if (!stat.isFile() || fileState(stat) !== state) throw new Error('Certificate storage changed during archive creation');
    }
    if ((await fs.promises.stat(archive)).size === 0) throw new Error('Certificate archive is empty');
    await new Promise((resolve, reject) => {
      res.download(archive, 'caddy-acme-certificates.tar.gz', {
        headers: { 'Content-Type': 'application/gzip', 'Cache-Control': 'no-store' }
      }, error => error ? reject(error) : resolve());
    });
  } catch (error) {
    if (!res.destroyed) {
      if (res.headersSent) res.destroy(error);
      else res.status(500).send('Failed to create certificate archive');
    }
  } finally {
    res.off('close', stopArchive);
    if (workspace) await fs.promises.rm(workspace, { recursive: true, force: true });
  }
}



router.get('/certs', async (req, res) => {
  try {
    res.json(await listCustomCertificateFiles());
  } catch (err) {
    res.status(500).send('Failed to read certs directory');
  }
});

router.post('/certs', upload.single('file'), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).send('Failed to get file');
  try {
    const filename = req.file.originalname;
    if (!isSafeFilename(filename) || !/\.(pem|crt|cer|key)$/i.test(filename)) {
      return res.status(400).send('Use a certificate (.pem, .crt, .cer) or private key (.key) filename');
    }
    const content = await fs.promises.readFile(req.file.path);
    try {
      if (/\.key$/i.test(filename)) crypto.createPrivateKey(content);
      else new crypto.X509Certificate(content);
    } catch {
      return res.status(400).send('Invalid certificate or unencrypted private key');
    }
    await fs.promises.chmod(req.file.path, 0o600);
    // Hard-linking publishes the complete upload and refuses to replace an existing certificate.
    await fs.promises.link(req.file.path, path.join(certDir, filename));
    res.sendStatus(200);
  } catch (err) {
    res.status(err.code === 'EEXIST' ? 409 : 500).send(err.code === 'EEXIST' ? 'A file with this name already exists; upload with a new name' : 'Failed to write file');
  } finally {
    await fs.promises.rm(req.file.path, { force: true });
  }
}));

router.delete('/certs', configHandler(async (req, res) => {
  const filename = req.query.file;
  if (!isSafeFilename(filename)) {
    return res.status(400).send('Invalid filename');
  }
  const removeReferences = req.query.removeReferences === '1';
  const filePath = path.join(certDir, filename);
  const removedPath = path.join(certDir, `.deleted-${crypto.randomUUID()}`);
  let moved = false;
  let committed = false;
  try {
    const file = fs.lstatSync(filePath);
    if (!file.isFile() && !file.isSymbolicLink()) throw configError(400, 'Certificate selection is not a file');
    const state = removeReferences ? requireConfigRevision(req) : configurationState();
    let assertRawUnchanged = () => {};
    if (state.mode === 'raw') {
      assertRawUnchanged = await require('./rawReferences').assertRawFileUnused(state.content || '', filename, {
        certDir, caddyfile: appPaths.caddyfile, execCaddy: execCaddyPromise
      });
    }
    const references = certificateReferencesForFiles([filename]);
    if (references.length > 0 && !removeReferences) return res.status(409).json({ error: 'Certificate is still referenced by the configuration', references });
    const removeFile = () => {
      assertRawUnchanged();
      fs.renameSync(filePath, removedPath);
      moved = true;
    };
    let clearedReferences = [];
    let writtenState = state;
    if (removeReferences) {
      const result = await clearCertificateReferencesForFiles([filename], state, removeFile);
      clearedReferences = result.cleared;
      writtenState = result.state;
    } else {
      db.transaction(() => {
        if (configurationState().etag !== state.etag) throw configError(412, 'Configuration changed; the file was not deleted');
        removeFile();
      }).immediate();
    }
    committed = true;
    await fs.promises.unlink(removedPath).catch(err => console.error('Failed to remove private certificate tombstone:', err.message));
    configHeaders(res, writtenState);
    res.json({ deleted: true, clearedReferences });
  } catch (err) {
    if (moved && !committed) {
      try {
        fs.linkSync(removedPath, filePath);
        fs.unlinkSync(removedPath);
      } catch (restoreError) {
        err = configError(restoreError.code === 'EEXIST' ? 409 : 500,
          `Certificate rollback could not reclaim its filename. Existing files were preserved; the previous file remains as ${path.basename(removedPath)}`);
      }
    }
    if (err.code === 'ENOENT') {
      res.status(404).send('File not found');
    } else {
      res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to delete file' });
    }
  }
}));

router.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).send('Certificate upload exceeds 10 MiB');
  next(err);
});

module.exports = router;
