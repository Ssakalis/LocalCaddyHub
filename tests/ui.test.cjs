const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadApp() {
    const fields = new Map();
    const $ = selector => {
        if (!fields.has(selector)) fields.set(selector, {
            value: '', properties: {}, length: 0,
            val(value) { if (!arguments.length) return this.value; this.value = value; return this; },
            prop(key, value) { if (arguments.length === 1) return this.properties[key]; this.properties[key] = value; return this; },
            ready() {}, text(value) { if (!arguments.length) return this.textValue; this.textValue = value; return this; }, html() { return this; },
            empty() { return this; }, append() { return this; }, show() { return this; }, hide() { return this; },
            removeClass() { return this; }, addClass() { return this; }
        });
        return fields.get(selector);
    };
    const document = { getElementById() { return null; } };
    const context = { window: {}, document, $, console: { error() {} }, setTimeout() {}, fetch() { throw new Error('unexpected request'); } };
    vm.runInNewContext(fs.readFileSync('static/app.js', 'utf8'), context);
    const app = context.window.app;
    app.ui.renderTable = app.ui.populateSelects = app.ui.syncAcmeControls = app.applyI18n = () => {};
    return { app, $, context };
}

test('row rendering preserves unsaved general settings', () => {
    const { app, $ } = loadApp();
    $('#genHttpPort').val('9080');
    app.ui.renderAll();
    assert.equal($('#genHttpPort').val(), '9080');
});

test('deleting a referenced access list cannot silently drop its protection', () => {
    const { app, context } = loadApp();
    context.confirm = () => true;
    app.config.domains = [{ id: 'domain', accesslist: ['management'] }];
    app.config.accessLists = [{ id: 'management', clientIps: ['10.0.0.0/8'] }];
    let reported = false;
    app.showStatus = (message, error) => { reported = error; };
    app.deleteItem('accessLists', 'management');
    assert.equal(app.config.accessLists.length, 1);
    assert.equal(reported, true);
});

test('failed initial config load cannot submit default configuration', async () => {
    const { app, context } = loadApp();
    context.fetch = async () => ({ ok: false, status: 503 });
    app.showStatus = () => {};
    await app.loadConfig();
    let posts = 0;
    context.fetch = async () => { posts++; return { ok: true }; };
    app.collectGeneralConfigFromForm = () => {};
    await app.saveStructuredConfig();
    assert.equal(posts, 0);
});

function configResponse(data, revision = '"loaded-base"', mode = 'structured') {
    return { ok: true, headers: new Headers({ ...(revision ? { ETag: revision } : {}), 'X-Config-Mode': mode }), json: async () => data };
}

test('config load binds the structured model to its own ETag and mode', async () => {
    const { app, context, $ } = loadApp();
    context.fetch = async url => url.endsWith('/structured')
        ? configResponse({ domains: [{ id: 'loaded-domain' }] }, '"structured-base"', 'raw')
        : configResponse({ content: '# newer raw view' }, '"newer-raw-base"', 'raw');
    await app.loadConfig();
    assert.equal(app.config.domains[0].id, 'loaded-domain');
    assert.equal(app.configRevision, '"structured-base"');
    assert.equal(app.configMode, 'raw');
    assert.equal(app.configLoaded, true);
    assert.equal($('#rawCaddyfile').val(), '# newer raw view');
});

test('a missing or weak config revision cannot replace the draft or enable saving', async () => {
    for (const revision of [null, 'W/"weak"']) {
        const { app, context } = loadApp();
        app.config.domains.push({ id: 'draft' });
        context.fetch = async () => configResponse({ domains: [{ id: 'server' }] }, revision);
        await app.loadConfig();
        assert.equal(app.configLoaded, false);
        assert.equal(app.config.domains[0].id, 'draft');
    }
});

test('replacing raw configuration requires confirmation and the original revision', async () => {
    const { app, context } = loadApp();
    app.configLoaded = true;
    app.configRevision = '"raw-base"';
    app.configMode = 'raw';
    app.config.domains.push({ id: 'draft' });
    app.collectGeneralConfigFromForm = () => {};
    app.showStatus = () => {};
    const requests = [];
    context.confirm = message => { assert.match(message, /replace.*raw/i); return false; };
    context.fetch = async (url, options) => {
        requests.push({ url, options });
        if (options?.method === 'POST') return { ok: true };
        return url.endsWith('/structured')
            ? configResponse({ domains: [{ id: 'saved' }] }, '"new-base"')
            : configResponse({ content: '# generated' }, '"new-base"');
    };
    assert.equal(await app.saveStructuredConfig(), false);
    assert.equal(requests.length, 0);
    assert.equal(app.config.domains[0].id, 'draft');
    assert.equal(app.configRevision, '"raw-base"');
    context.confirm = () => true;
    assert.equal(await app.saveStructuredConfig(), true);
    assert.equal(requests[0].options.headers['If-Match'], '"raw-base"');
    assert.equal(requests[0].options.headers['X-Config-Mode'], 'structured');
    assert.equal(app.configRevision, '"new-base"');
    assert.equal(app.configMode, 'structured');
    assert.equal(app.config.domains[0].id, 'saved');
});

test('failed RSA configuration leaves the selected certificate key type unchanged', async () => {
    const { app, context, $ } = loadApp();
    app.configLoaded = true;
    app.configRevision = '"draft-base"';
    app.config.general.tls_key_type = 'p256';
    $('#genTlsKeyType').val('p256');
    context.confirm = () => true;
    context.fetch = async () => ({ ok: false, json: async () => ({ error: 'Caddy unavailable' }) });
    await app.renewAllManagedCertificatesAsRsa();
    assert.equal(app.config.general.tls_key_type, 'p256');
    assert.equal($('#genTlsKeyType').val(), 'p256');
});

test('saving sends the draft base revision and retains the entire draft on conflict', async () => {
    const { app, context } = loadApp();
    app.configLoaded = true;
    app.configRevision = '"old-revision"';
    app.config.domains.push({ id: 'unsaved-domain' });
    app.collectGeneralConfigFromForm = () => {};
    app.showStatus = () => {};
    let request;
    context.fetch = async (url, options) => {
        request = options;
        return { ok: false, status: 412, text: async () => 'Configuration changed' };
    };
    assert.equal(await app.saveStructuredConfig(), false);
    assert.equal(request.headers['If-Match'], '"old-revision"');
    assert.equal(app.config.domains[0].id, 'unsaved-domain');
    assert.equal(app.configRevision, '"old-revision"');
});

test('save conflicts explain reconciliation without fetching or replacing the draft', async () => {
    for (const status of [409, 412, 428]) {
        const { app, context } = loadApp();
        app.configLoaded = true;
        app.configRevision = '"draft-base"';
        app.configMode = 'structured';
        app.config.domains.push({ id: 'draft' });
        app.collectGeneralConfigFromForm = () => {};
        let message;
        app.showStatus = value => { message = value; };
        let requests = 0;
        context.fetch = async () => { requests++; return { ok: false, status }; };
        assert.equal(await app.saveStructuredConfig(), false);
        assert.equal(requests, 1);
        assert.equal(app.config.domains[0].id, 'draft');
        assert.equal(app.configRevision, '"draft-base"');
        assert.equal(app.configMode, 'structured');
        assert.match(message, /draft|unsaved edits/i);
        assert.match(message, /reload/i);
    }
});

test('configuration-changing certificate actions send the draft revision and preserve local edits after success', async () => {
    for (const action of ['rsa', 'cleanup', 'delete']) {
        const { app, context, $ } = loadApp();
        app.configLoaded = true;
        app.configRevision = '"draft-base"';
        app.configMode = 'structured';
        app.config.domains.push({ id: 'draft', customCert: 'mail.pem' });
        app.config.general.tls_key_type = 'p256';
        app.missingCertReferences = [{ file: 'missing.pem' }];
        context.confirm = () => true;
        let message;
        context.alert = value => { message = value; };
        app.loadConfig = async () => { throw new Error('must not reload the configuration draft'); };
        app.loadCerts = app.loadPfxCertificates = app.loadMissingCertificateReferences = async () => {};
        app.pollLetsEncryptStatus = () => {};
        const requests = [];
        context.fetch = async (url, options) => {
            requests.push({ url, options });
            if (action === 'delete' && requests.length === 1) return { ok: false, status: 409, json: async () => ({ references: [{ type: 'Domain', owner: 'mail' }] }) };
            return configResponse({ output: 'Updated' }, '"server-new-base"');
        };
        if (action === 'rsa') {
            await app.renewAllManagedCertificatesAsRsa();
            message = $('#certRenewStatus').text();
        } else if (action === 'cleanup') {
            await app.cleanupMissingCertificateReferences();
            message = $('#certReferenceStatus').text();
        } else await app.deleteCert('mail.pem');
        const write = requests.at(-1);
        assert.equal(write.options.headers['If-Match'], '"draft-base"', action);
        assert.equal(app.config.domains[0].id, 'draft', action);
        assert.equal(app.config.domains[0].customCert, 'mail.pem', action);
        assert.equal(app.config.general.tls_key_type, 'p256', action);
        assert.equal(app.configRevision, '"draft-base"', action);
        assert.equal(app.configMode, 'structured', action);
        assert.match(message, /reload/i, action);
        assert.match(message, /draft|unsaved edits/i, action);
    }
});

test('configuration-changing certificate conflicts preserve drafts and report how to reconcile', async () => {
    for (const action of ['rsa', 'cleanup', 'delete']) {
        const { app, context, $ } = loadApp();
        app.configLoaded = true;
        app.configRevision = '"draft-base"';
        app.config.domains.push({ id: 'draft' });
        app.missingCertReferences = [{ file: 'missing.pem' }];
        context.confirm = () => true;
        let message;
        context.alert = value => { message = value; };
        app.loadConfig = async () => { throw new Error('must not reload the configuration draft'); };
        let writes = 0;
        context.fetch = async (url, options) => {
            assert.ok(options?.method === 'POST' || options?.method === 'DELETE', 'conflicts must not reload configuration');
            writes++;
            if (action === 'delete' && writes === 1) return { ok: false, status: 409, json: async () => ({ references: [] }) };
            assert.equal(options.headers['If-Match'], '"draft-base"');
            return { ok: false, status: 412, json: async () => ({ error: 'Revision mismatch' }) };
        };
        if (action === 'rsa') {
            await app.renewAllManagedCertificatesAsRsa();
            message = $('#certRenewStatus').text();
        } else if (action === 'cleanup') {
            await app.cleanupMissingCertificateReferences();
            message = $('#certReferenceStatus').text();
        } else await app.deleteCert('mail.pem');
        assert.equal(app.configRevision, '"draft-base"', action);
        assert.equal(app.config.domains[0].id, 'draft', action);
        assert.match(message, /changed on the server/i, action);
        assert.match(message, /draft|unsaved edits/i, action);
        assert.match(message, /reload/i, action);
    }
});

test('certificate-only reload preserves configuration draft and its original revision', async () => {
    const { app, context } = loadApp();
    app.configRevision = '"draft-base"';
    app.config.general.log_level = 'unsaved';
    app.pfxCertificates = [{ id: 'managed', renewable: true, name: 'test' }];
    context.confirm = () => true;
    app.loadPfxCertificates = async () => {};
    app.pollLetsEncryptStatus = () => {};
    context.fetch = async () => ({ ok: true, json: async () => ({ output: 'reloaded' }) });
    await app.renewManagedCertificate('managed');
    assert.equal(app.config.general.log_level, 'unsaved');
    assert.equal(app.configRevision, '"draft-base"');
});

test('invalid modal data remains open without mutating configuration', () => {
    const { app, context } = loadApp();
    let reported = false;
    context.document.getElementById = () => ({ checkValidity: () => false, reportValidity() { reported = true; }, querySelector: () => null });
    context.FormData = class { constructor() { throw new Error('invalid form must not be serialized'); } };
    app.ui.saveModal('domainModal', 'domains');
    assert.equal(reported, true);
    assert.equal(app.config.domains.length, 0);
});

test('HTML escaping keeps attacker-controlled log strings inert', () => {
    const { app } = loadApp();
    assert.equal(app.escapeHtml('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
});

test('structured log filtering tolerates non-string fields', () => {
    const { app } = loadApp();
    app.logFiltersCache.level = 'error';
    assert.equal(app.passesLogFilters('', '', { level: 5 }), false);
    app.logFiltersCache.level = '';
    app.logFiltersCache.method = 'GET';
    assert.equal(app.passesLogFilters('', '', { request: { method: 5 } }), false);
});

test('log formatting preserves zero and safely formats object values', () => {
    const { app } = loadApp();
    assert.equal(app.escapeHtml(0), '0');
    assert.equal(app.escapeHtml({ toString: '<img onerror=alert(1)>' }), '{&quot;toString&quot;:&quot;&lt;img onerror=alert(1)&gt;&quot;}');
});

test('JSON null log lines use the plain-text renderer', () => {
    const { app, context, $ } = loadApp();
    context.EventSource = class { close() {} };
    $('#logFileSelect').val('access.log');
    let formattedAsJson;
    app.appendLogLine = (line, raw, data, isJson) => { formattedAsJson = isJson; };
    app.startTailing();
    app.logStreamSource.onmessage({ data: 'null' });
    assert.equal(formattedAsJson, false);
});
