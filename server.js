const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;

// ---- Settings ----
const MAX_LOGS = 200;
const MAX_DEVICES = 500;
const BASIC_USERNAME = process.env.BASIC_USERNAME || 'nexrelay_admin';
const INBOUND_TOKEN = process.env.INBOUND_TOKEN || '';
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '.service-now.com')
    .split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
const OUTBOUND_TIMEOUT_MS = 30000;
const OAUTH_TOKEN_TTL_S = Number(process.env.OAUTH_TOKEN_TTL_S) || 3600;
const OAUTH_MAX_TOKENS = 20;
const DEVICE_ID_RE = /^sn_dev_[a-f0-9]{48}$/;
const GLOBAL_ID = 'default_global';

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    next();
});
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '20kb' }));

// ---- Stores ----
const deviceStores = new Map();
const sessions = new Map();

function evict(map) {
    while (map.size > MAX_DEVICES) map.delete(map.keys().next().value);
}

function getStore(deviceId) {
    const id = DEVICE_ID_RE.test(deviceId || '') ? deviceId : GLOBAL_ID;
    let store = deviceStores.get(id);
    if (!store) store = { inbound: [], outbound: [] };
    deviceStores.delete(id);
    deviceStores.set(id, store);
    evict(deviceStores);
    return store;
}

function addLog(list, entry) {
    list.unshift(entry);
    if (list.length > MAX_LOGS) list.length = MAX_LOGS;
}

function safeParse(text) {
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
}

function isAllowedUrl(rawUrl) {
    try {
        const u = new URL(rawUrl);
        if (u.protocol !== 'https:') return false;
        const host = u.hostname.toLowerCase();
        return ALLOWED_HOSTS.some(rule =>
            rule === '*' || (rule.startsWith('.') ? host.endsWith(rule) : host === rule)
        );
    } catch { return false; }
}

// ---- Credential helpers ----
const digest = v => crypto.createHash('sha256').update(String(v)).digest();
const matches = (candidate, storedDigest) => crypto.timingSafeEqual(digest(candidate), storedDigest);
const randomSecret = (prefix, bytes) => prefix + crypto.randomBytes(bytes).toString('hex');
const newSyncId = prefix => prefix + crypto.randomInt(100000, 1000000);
const sameText = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

function hasValidOAuthToken(session, candidate) {
    const now = Date.now();
    session.tokens = session.tokens.filter(t => t.exp > now);
    let ok = false;
    for (const t of session.tokens) {
        if (matches(candidate, t.digest)) ok = true;
    }
    return ok;
}

function authenticateInbound(req, session) {
    const auth = req.headers['authorization'] || '';
    const headerKey = req.headers['x-sn-apikey'] || req.headers['x-api-key'] || '';

    if (INBOUND_TOKEN && auth === 'Bearer ' + INBOUND_TOKEN) return 'Static Bearer Token';
    if (!session) return null;

    if (auth.startsWith('Bearer ')) {
        const candidate = auth.slice(7).trim();
        if (candidate && matches(candidate, session.bearer)) return 'Bearer Token';
        if (candidate && hasValidOAuthToken(session, candidate)) return 'OAuth 2.0 (Client Credentials)';
    }
    if (auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx > -1) {
            const user = decoded.slice(0, idx);
            const pass = decoded.slice(idx + 1);
            if (sameText(user, BASIC_USERNAME) && matches(pass, session.password)) return 'Basic Auth';
        }
    }
    if (headerKey && matches(headerKey, session.apiKey)) return 'API Key (Header)';
    return null;
}

function deviceFrom(req, res) {
    const id = String(req.headers['x-device-token'] || '').trim();
    if (!DEVICE_ID_RE.test(id)) {
        res.status(400).json({ status: 'Error', message: 'Missing or invalid X-Device-Token header.' });
        return null;
    }
    return id;
}

// 0. Credential Issuing Endpoint
app.post('/api/v1/servicenow/session', (req, res) => {
    const deviceId = String((req.body && req.body.deviceId) || '');
    if (!DEVICE_ID_RE.test(deviceId)) {
        return res.status(400).json({ status: 'Error', message: 'Invalid deviceId.' });
    }
    const creds = {
        username: BASIC_USERNAME,
        clientId: 'nexrelay_' + deviceId.slice(7, 19),
        password: randomSecret('sn_pass_', 16),
        apiKey: randomSecret('sn_key_', 20),
        bearer: randomSecret('sn_nex_', 24),
        clientSecret: randomSecret('sn_sec_', 24)
    };
    sessions.delete(deviceId);
    sessions.set(deviceId, {
        bearer: digest(creds.bearer),
        apiKey: digest(creds.apiKey),
        password: digest(creds.password),
        clientId: digest(creds.clientId),
        clientSecret: digest(creds.clientSecret),
        tokens: []
    });
    evict(sessions);
    res.set('Cache-Control', 'no-store');
    res.json({ ...creds, tokenTtlSeconds: OAUTH_TOKEN_TTL_S, allowedHosts: ALLOWED_HOSTS });
});

// 0b. OAuth 2.0 Token Endpoint
app.post('/api/v1/servicenow/oauth/token/:deviceToken', (req, res) => {
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
    const id = String(req.params.deviceToken || '');
    const session = DEVICE_ID_RE.test(id) ? sessions.get(id) : null;
    const body = req.body || {};

    if (body.grant_type !== 'client_credentials') {
        return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Only the client_credentials grant is supported.'
        });
    }

    let clientId = typeof body.client_id === 'string' ? body.client_id : '';
    let clientSecret = typeof body.client_secret === 'string' ? body.client_secret : '';
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx > -1) { clientId = decoded.slice(0, idx); clientSecret = decoded.slice(idx + 1); }
    }

    const valid = session && clientId && clientSecret &&
        matches(clientId, session.clientId) && matches(clientSecret, session.clientSecret);
    if (!valid) {
        res.set('WWW-Authenticate', 'Basic realm="NexRelay OAuth"');
        return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client or wrong secret.' });
    }

    const accessToken = randomSecret('sn_oat_', 24);
    session.tokens = session.tokens
        .filter(t => t.exp > Date.now())
        .concat({ digest: digest(accessToken), exp: Date.now() + OAUTH_TOKEN_TTL_S * 1000 })
        .slice(-OAUTH_MAX_TOKENS);

    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: OAUTH_TOKEN_TTL_S });
});

// 1. ServiceNow Inbound Webhook Endpoint
app.post(['/api/v1/servicenow/inbound/:deviceToken', '/api/v1/servicenow/inbound'], (req, res) => {
    const requested = String(req.params.deviceToken || req.headers['x-device-token'] || '').trim();
    if (requested && !DEVICE_ID_RE.test(requested)) {
        return res.status(400).json({ status: 'Error', message: 'Invalid device token in URL or X-Device-Token header.' });
    }

    const session = requested ? sessions.get(requested) : null;
    const authMethod = authenticateInbound(req, session);
    if (!authMethod) {
        res.set('WWW-Authenticate', 'Bearer realm="NexRelay"');
        return res.status(401).json({
            status: 'Error',
            message: 'Authentication failed: Provide a valid Bearer token, Basic credentials, API key, or OAuth access token.'
        });
    }

    const store = getStore(requested);
    const syncId = newSyncId('SN-INB-');
    const inboundEntry = {
        id: syncId,
        direction: 'INBOUND',
        authMethod,
        timestamp: new Date().toISOString(),
        headers: { 'content-type': req.headers['content-type'] },
        payload: req.body
    };

    addLog(store.inbound, inboundEntry);
    res.status(200).json({
        status: 'Success',
        message: 'Inbound ServiceNow payload successfully ingested.',
        record: inboundEntry
    });
});

// 2. Outbound HTTP Proxy Endpoint
app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);

    const { method, url, authType, basicUser, basicPass, bearerToken, apiKeyHeaderName, apiKeyValue, headers, body } = req.body || {};

    if (!url || !method) {
        return res.status(400).json({
            status: 'Error',
            message: 'Validation Error: Both HTTP Method and Target Endpoint URL are required.'
        });
    }

    if (!isAllowedUrl(url)) {
        return res.status(400).json({
            status: 'Error',
            message: 'Blocked: only https URLs on these hosts are allowed: ' + ALLOWED_HOSTS.join(', ') + '.'
        });
    }

    const syncId = newSyncId('SN-OUT-');
    const timestamp = new Date().toISOString();
    const startTime = Date.now();

    const requestHeaders = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    };

    if (headers && typeof headers === 'object') {
        Object.entries(headers).forEach(([k, v]) => {
            if (k && k.trim()) requestHeaders[k.trim()] = v;
        });
    }

    if (authType === 'basic' && basicUser) {
        const combined = `${basicUser}:${basicPass || ''}`;
        requestHeaders['Authorization'] = 'Basic ' + Buffer.from(combined).toString('base64');
    } else if (authType === 'bearer' && bearerToken) {
        requestHeaders['Authorization'] = `Bearer ${bearerToken}`;
    } else if (authType === 'apikey' && apiKeyValue) {
        const headerName = (apiKeyHeaderName && apiKeyHeaderName.trim()) ? apiKeyHeaderName.trim() : 'x-sn-apikey';
        requestHeaders[headerName] = apiKeyValue;
    }

    const fetchOptions = {
        method: String(method).toUpperCase(),
        headers: requestHeaders
    };

    if (['POST', 'PUT', 'PATCH'].includes(fetchOptions.method) && body) {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    let responseStatus = 200;
    let statusText = 'OK';
    let responseData = null;
    let durationMs = 0;
    let diagnosticError = null;

    try {
        const response = await fetch(url, {
            ...fetchOptions,
            redirect: 'manual',
            signal: AbortSignal.timeout(OUTBOUND_TIMEOUT_MS)
        });
        durationMs = Date.now() - startTime;
        responseStatus = response.status;
        statusText = response.statusText;

        const rawText = await response.text();
        try {
            responseData = JSON.parse(rawText);
        } catch {
            responseData = rawText || { message: 'Response body returned empty or non-JSON format.' };
        }
    } catch (error) {
        durationMs = Date.now() - startTime;
        responseStatus = 503;
        statusText = error.name === 'TimeoutError' ? 'Request Timed Out' : 'Network DNS or TLS Failure';
        diagnosticError = error.message;
        responseData = {
            error: error.message,
            diagnosticAdvice: 'Verify that your ServiceNow instance is online and reachable.'
        };
    }

    const outboundEntry = {
        id: syncId,
        direction: 'OUTBOUND',
        method: fetchOptions.method,
        url,
        status: `${responseStatus} ${statusText}`,
        statusCode: responseStatus,
        durationMs,
        timestamp,
        diagnosticError,
        requestPayload: safeParse(fetchOptions.body),
        responsePayload: responseData
    };

    addLog(store.outbound, outboundEntry);
    res.status(200).json({ status: 'Completed', record: outboundEntry });
});

// 2b. Device-scoped log endpoints
app.get('/api/v1/servicenow/logs', (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);
    res.set('Cache-Control', 'no-store');
    res.json({ inbound: store.inbound, outbound: store.outbound });
});

app.delete('/api/v1/servicenow/logs', (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);
    const deleted = store.inbound.length + store.outbound.length;
    store.inbound = [];
    store.outbound = [];
    res.json({ status: 'Cleared', deleted });
});

app.delete('/api/v1/servicenow/logs/:id', (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);
    const targetId = req.params.id;

    const before = store.inbound.length + store.outbound.length;
    store.inbound = store.inbound.filter(item => item.id !== targetId);
    store.outbound = store.outbound.filter(item => item.id !== targetId);

    if (store.inbound.length + store.outbound.length === before) {
        return res.status(404).json({ status: 'Error', message: 'Record not found in this device session.' });
    }
    res.json({ status: 'Success', message: `Record ${targetId} deleted.`, deleted: 1 });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
});

// 3. Frontend UI (Enterprise Pro Edition)
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexRelay · Enterprise ServiceNow Integration Hub</title>
<style>
:root{
  --bg:#030712;--surface:#0b1120;--surface-2:#111827;--border:#1f2937;--border-strong:#374151;
  --text:#f9fafb;--muted:#9ca3af;--accent:#10b981;--accent-hover:#059669;--accent-ink:#ffffff;--accent-soft:#064e3b;
  --danger:#ef4444;--danger-hover:#dc2626;--danger-soft:#7f1d1d;--ok:#10b981;--ok-soft:#064e3b;
  --warn:#f59e0b;--warn-soft:#78350f;--info:#38bdf8;--info-soft:#0c4a6e;
  --side:#020617;--side-text:#94a3b8;--side-active:#0f172a;
  --shadow:0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
  --shadow-lg:0 25px 50px -12px rgba(0, 0, 0, 0.7);
  --blue:#38bdf8;--blue-bg:#082f49;--blue-bd:#0369a1;
  --violet:#a78bfa;--violet-bg:#2e1065;--violet-bd:#6d28d9;
  --amber:#fbbf24;--amber-bg:#451a03;--amber-bd:#b45309;
  --green:#34d399;--green-bg:#064e3b;--green-bd:#047857;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;-webkit-font-smoothing:antialiased}
[hidden]{display:none!important}
button{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

.app{display:grid;grid-template-columns:268px minmax(0,1fr);min-height:100vh}
.sidebar{background:var(--side);color:var(--side-text);display:flex;flex-direction:column;padding:24px 16px;position:sticky;top:0;height:100vh;border-right:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:12px;padding:4px 8px 28px}
.brand-mark{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#10b981,#059669);display:grid;place-items:center;color:#fff;box-shadow:0 0 25px rgba(16,185,129,0.35)}
.brand-mark .icon{width:22px;height:22px}
.brand strong{display:block;color:#fff;font-size:16px;letter-spacing:.3px}
.brand span{font-size:12px;color:var(--muted)}
.nav{display:flex;flex-direction:column;gap:6px}
.nav-label{font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;padding:0 12px 8px;color:var(--muted)}
.nav-item{display:flex;align-items:center;gap:12px;width:100%;padding:11px 14px;border:0;border-radius:10px;background:transparent;color:var(--side-text);font-weight:500;text-align:left;cursor:pointer;transition:all .2s ease}
.nav-item:hover{background:rgba(255,255,255,.05);color:#fff}
.nav-item.active{background:var(--side-active);color:#fff;box-shadow:inset 3px 0 0 var(--accent);border:1px solid rgba(255,255,255,.04)}
.count{margin-left:auto;min-width:24px;padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.1);color:#fff;font-size:11px;font-weight:600;text-align:center}
.side-foot{margin-top:auto;padding:16px 12px 0;border-top:1px solid var(--border);font-size:12px}
.side-foot .lbl{text-transform:uppercase;letter-spacing:.8px;font-size:10px;color:var(--muted);margin-bottom:6px}
.side-foot code{display:block;color:var(--text);font-family:var(--mono);margin-bottom:12px;background:var(--surface);padding:8px 10px;border-radius:8px;border:1px solid var(--border);font-size:11px}
.btn-side{width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer;font-weight:500;transition:all .15s}
.btn-side:hover{background:var(--surface-2);border-color:var(--accent)}

.main{padding:32px 40px 64px;width:100%;max-width:1280px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:28px}
.topbar h1{margin:0;font-size:26px;font-weight:700;letter-spacing:-.4px}
.topbar p{margin:6px 0 0;color:var(--muted);font-size:14px}
.status{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:12px;font-weight:600;white-space:nowrap;box-shadow:var(--shadow)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.status.ok .dot{background:var(--ok);box-shadow:0 0 0 4px var(--ok-soft)}
.status.bad .dot{background:var(--danger);box-shadow:0 0 0 4px var(--danger-soft)}

/* Metrics Telemetry Bar */
.metrics-bar{display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:28px}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;box-shadow:var(--shadow)}
.metric-card .label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:6px}
.metric-card .value{font-size:22px;font-weight:700;font-family:var(--mono);color:var(--text)}

.panel{display:none}
.panel.active{display:block;animation:fadeIn .25s ease}

.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;box-shadow:var(--shadow);margin-bottom:24px;overflow:hidden}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 26px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.01)}
.card-head h2{margin:0;font-size:17px;font-weight:650}
.card-head p{margin:4px 0 0;color:var(--muted);font-size:13px}
.card-body{padding:26px}

label{display:block;margin-bottom:8px;font-size:11.5px;font-weight:700;color:var(--muted);letter-spacing:.5px;text-transform:uppercase}
.field{margin-bottom:20px}
.field:last-child{margin-bottom:0}
input,select,textarea{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border-strong);border-radius:10px;padding:11px 16px;font:inherit;transition:border-color .15s,box-shadow .15s}
textarea{font-family:var(--mono);font-size:13px;resize:vertical;min-height:160px}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);outline:none}
.input-group{display:flex;align-items:stretch;border:1px solid var(--border-strong);border-radius:10px;background:var(--bg);overflow:hidden;transition:border-color .15s,box-shadow .15s}
.input-group:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.input-group input{border:0;background:transparent;border-radius:0;font-family:var(--mono);font-size:13px;padding:11px 16px}
.input-group input:focus-visible{outline:none}
.icon-btn{display:inline-grid;place-items:center;width:44px;flex:none;border:0;border-left:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;transition:all .15s}
.icon-btn:hover{background:var(--accent-soft);color:var(--accent)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 20px;border-radius:10px;border:1px solid transparent;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}
.btn-sm{padding:7px 14px;font-size:13px}
.btn-primary{background:var(--accent);color:var(--accent-ink)}
.btn-primary:hover{background:var(--accent-hover)}
.btn-secondary{background:var(--surface);color:var(--text);border-color:var(--border-strong)}
.btn-secondary:hover{background:var(--surface-2);border-color:var(--border)}
.btn-danger-ghost{background:transparent;color:var(--danger);border-color:var(--border-strong)}
.btn-danger-ghost:hover{background:var(--danger-soft);border-color:var(--danger)}

.seg{display:inline-flex;padding:4px;gap:4px;background:var(--bg);border:1px solid var(--border);border-radius:12px;margin-bottom:24px}
.seg button{border:0;background:transparent;padding:8px 18px;border-radius:9px;font-weight:600;color:var(--muted);cursor:pointer;transition:all .15s}
.seg button:hover{color:var(--text)}
.seg button.active{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}

/* Quick Templates Bar */
.templates-bar{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
.template-chip{background:var(--surface-2);border:1px solid var(--border-strong);color:var(--text);padding:6px 12px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s}
.template-chip:hover{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}

.url-bar{display:grid;grid-template-columns:130px minmax(0,1fr) auto;gap:12px;margin-bottom:24px}
.url-bar select{font-weight:700}
.url-bar input{font-family:var(--mono);font-size:13px}
.header-row{display:grid;grid-template-columns:1fr 1fr 44px;gap:12px;margin-bottom:12px}
.header-row .icon-btn{border:1px solid var(--border-strong);border-radius:10px}
.hint{margin:12px 0 0;color:var(--muted);font-size:13px}
.hint b{color:var(--text);font-weight:600}

.tag{font-family:var(--mono);font-weight:700;font-size:13px;letter-spacing:.3px;text-align:center;cursor:default;border:1px solid;user-select:all}
.tag-blue{color:var(--blue);background:var(--blue-bg);border-color:var(--blue-bd)}
.tag-violet{color:var(--violet);background:var(--violet-bg);border-color:var(--violet-bd)}
.tag-amber{color:var(--amber);background:var(--amber-bg);border-color:var(--amber-bd)}
.tag-green{color:var(--green);background:var(--green-bg);border-color:var(--green-bd)}
.auth-row{display:grid;grid-template-columns:180px 130px minmax(0,1fr);gap:14px;align-items:end;margin-bottom:16px}
.auth-row.two{grid-template-columns:180px minmax(0,1fr)}
.auth-row.opt{grid-template-columns:140px 180px minmax(0,1fr)}
.auth-row .field{margin-bottom:0}
.note-cell{padding:10px 0;color:var(--muted);font-size:13px}
.note-cell code{font-family:var(--mono);color:var(--text);background:var(--bg);padding:2px 6px;border-radius:4px;border:1px solid var(--border)}
.opt-title{margin:24px 0 12px;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}
.panel-actions{margin:4px 0 6px}

.toolbar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.toolbar .seg{margin:0}
.spacer{flex:1}

.log{background:var(--surface);border:1px solid var(--border);border-radius:16px;box-shadow:var(--shadow);margin-bottom:16px;overflow:hidden}
.log-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:18px 24px}
.log-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0}
.log-id{font-family:var(--mono);font-size:13px;font-weight:600}
.log-meta{color:var(--muted);font-size:12.5px}
.log-actions{display:flex;align-items:center;gap:14px}
.log-url{padding:0 24px 14px;font-family:var(--mono);font-size:12.5px;color:var(--muted);word-break:break-all}
.log details{border-top:1px solid var(--border)}
.log summary{padding:14px 24px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;user-select:none}
.log summary:hover{color:var(--text)}
.block{padding:0 24px 20px}
.block-label{margin-bottom:8px;font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted)}
pre{margin:0;padding:18px;background:var(--bg);border:1px solid var(--border);border-radius:12px;font:13px/1.6 var(--mono);overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-word}
.trunc{margin-top:8px;font-size:12.5px;color:var(--warn)}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:700;letter-spacing:.3px}
.b-info{background:var(--info-soft);color:var(--info)}
.b-ok{background:var(--ok-soft);color:var(--ok)}
.b-warn{background:var(--warn-soft);color:var(--warn)}
.b-err{background:var(--danger-soft);color:var(--danger)}
.b-neutral{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.empty{display:grid;place-items:center;gap:10px;text-align:center;padding:64px 20px;border:1px dashed var(--border-strong);border-radius:16px;color:var(--muted);background:var(--surface)}
.empty .icon{width:32px;height:32px}
.empty strong{color:var(--text);font-size:15px}

.toasts{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:10px;z-index:60}
.toast{min-width:260px;max-width:400px;padding:14px 18px;border-radius:12px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--info);box-shadow:var(--shadow-lg);font-size:13.5px;animation:fadeIn .2s ease}
.toast.success{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--danger)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,0.75);display:grid;place-items:center;padding:20px;z-index:80;backdrop-filter:blur(6px)}
.dialog{width:100%;max-width:440px;background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:var(--shadow-lg)}
.dialog h3{margin:0 0 10px;font-size:18px}
.dialog p{margin:0 0 24px;color:var(--muted)}
.dialog .actions{display:flex;justify-content:flex-end;gap:12px}

@media (max-width:900px){
  .app{grid-template-columns:1fr}
  .sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:12px;padding:16px}
  .brand{padding:0}.nav-label,.side-foot{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .main{padding:24px 16px 56px}
  .grid-2,.url-bar,.metrics-bar{grid-template-columns:1fr}
  .topbar{flex-direction:column}
}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="i-in" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></symbol>
  <symbol id="i-out" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></symbol>
  <symbol id="i-list" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
  <symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></symbol>
  <symbol id="i-refresh" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></symbol>
  <symbol id="i-hex" viewBox="0 0 24 24"><path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M8 12h8"/><path d="M13 9l3 3-3 3"/></symbol>
  <symbol id="i-send" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></symbol>
  <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
</svg>

<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark"><svg class="icon"><use href="#i-hex"/></svg></div>
      <div><strong>NexRelay</strong><span>Enterprise Hub</span></div>
    </div>
    <div class="nav-label">Workspace</div>
    <nav class="nav" aria-label="Primary">
      <button type="button" class="nav-item active" data-panel="inbound"><svg class="icon"><use href="#i-in"/></svg>Inbound Webhook</button>
      <button type="button" class="nav-item" data-panel="outbound"><svg class="icon"><use href="#i-out"/></svg>Outbound Client</button>
      <button type="button" class="nav-item" data-panel="logs"><svg class="icon"><use href="#i-list"/></svg>Execution Logs<span class="count" id="logCount">0</span></button>
    </nav>
    <div class="side-foot">
      <div class="lbl">Workspace ID</div>
      <code id="deviceIdBadge">—</code>
      <button type="button" class="btn-side" id="newSessionBtn">New Workspace</button>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div><h1 id="pageTitle"></h1><p id="pageSub"></p></div>
      <div class="status" id="statusPill"><span class="dot"></span><span id="statusText">Checking gateway…</span></div>
    </header>

    <!-- Metrics Telemetry Bar -->
    <div class="metrics-bar">
      <div class="metric-card">
        <div class="label">Total Requests</div>
        <div class="value" id="metricTotal">0</div>
      </div>
      <div class="metric-card">
        <div class="label">Success Rate</div>
        <div class="value" id="metricSuccess">100%</div>
      </div>
      <div class="metric-card">
        <div class="label">Avg Latency</div>
        <div class="value" id="metricLatency">0 ms</div>
      </div>
      <div class="metric-card">
        <div class="label">Active Sessions</div>
        <div class="value" id="metricSession">Secure</div>
      </div>
    </div>

    <!-- Inbound -->
    <section id="panel-inbound" class="panel active">
      <div class="card">
        <div class="card-head"><div><h2>Secure Webhook Endpoint URL</h2><p>Pristine, secret-free URL route. Secrets are strictly handled via authorization headers.</p></div></div>
        <div class="card-body">
          <div class="field">
            <label for="inboundUrlBox">Endpoint URL</label>
            <div class="input-group">
              <input type="text" id="inboundUrlBox" readonly spellcheck="false">
              <button type="button" class="icon-btn" data-copy="inboundUrlBox" data-label="Endpoint URL" title="Copy" aria-label="Copy endpoint URL"><svg class="icon"><use href="#i-copy"/></svg></button>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>Authentication Credentials</h2><p>Cryptographically secure tokens rotating on demand. Completely secret-free in URLs.</p></div>
          <button type="button" class="btn btn-secondary btn-sm" id="rotateBtn"><svg class="icon"><use href="#i-refresh"/></svg>Rotate Credentials</button>
        </div>
        <div class="card-body">
          <div class="seg" role="tablist" aria-label="Authentication method">
            <button type="button" class="active" data-tab-group="cred" data-tab-target="cred-bearer">Bearer Token</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-basic">Basic Auth</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-key">API Key</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-oauth">OAuth 2.0</button>
          </div>

          <!-- Bearer -->
          <div class="tab-panel" data-panel-group="cred" id="cred-bearer">
            <div class="auth-row">
              <div class="field">
                <label for="bearerHeaderName">Header</label>
                <input type="text" id="bearerHeaderName" class="tag tag-blue" value="Authorization" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="field">
                <label for="bearerScheme">Scheme</label>
                <input type="text" id="bearerScheme" class="tag tag-violet" value="Bearer" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="field">
                <label for="bearerBox">Token</label>
                <div class="input-group">
                  <input type="password" id="bearerBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-reveal="bearerBox" title="Show / hide" aria-label="Show or hide token"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="bearerBox" data-label="Bearer token" title="Copy token" aria-label="Copy token"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <div class="panel-actions">
              <button type="button" class="btn btn-secondary btn-sm" data-copy-header><svg class="icon"><use href="#i-copy"/></svg>Copy Header Value</button>
            </div>
            <p class="hint">In ServiceNow REST Message, add an HTTP header named <b>Authorization</b> with value <b>Bearer &lt;token&gt;</b>.</p>
          </div>

          <!-- Basic -->
          <div class="tab-panel" data-panel-group="cred" id="cred-basic" hidden>
            <div class="grid-2">
              <div class="field">
                <label for="basicUserBox">Username (Permanent)</label>
                <div class="input-group">
                  <input type="text" id="basicUserBox" readonly spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-copy="basicUserBox" data-label="Username" title="Copy" aria-label="Copy username"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="field">
                <label for="basicPassBox">Password</label>
                <div class="input-group">
                  <input type="password" id="basicPassBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-reveal="basicPassBox" title="Show / hide" aria-label="Show or hide password"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="basicPassBox" data-label="Password" title="Copy" aria-label="Copy password"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint">In ServiceNow, set the REST Message Authentication type to <b>Basic</b>.</p>
          </div>

          <!-- API Key -->
          <div class="tab-panel" data-panel-group="cred" id="cred-key" hidden>
            <div class="field">
              <label for="apiKeyBox">API Key</label>
              <div class="input-group">
                <input type="password" id="apiKeyBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                <button type="button" class="icon-btn" data-reveal="apiKeyBox" title="Show / hide" aria-label="Show or hide API key"><svg class="icon"><use href="#i-eye"/></svg></button>
                <button type="button" class="icon-btn" data-copy="apiKeyBox" data-label="API key" title="Copy" aria-label="Copy API key"><svg class="icon"><use href="#i-copy"/></svg></button>
              </div>
            </div>

            <div class="opt-title">Header Authentication (Secure & Recommended)</div>
            <div class="auth-row opt">
              <div class="field">
                <label for="keyViaHeader">Delivery</label>
                <input type="text" id="keyViaHeader" class="tag tag-amber" value="HTTP Header" readonly aria-readonly="true">
              </div>
              <div class="field">
                <label for="keyHeaderName">Header Name</label>
                <input type="text" id="keyHeaderName" class="tag tag-green" value="x-sn-apikey" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="note-cell">Pass key securely in header. URLs remain completely clean.</div>
            </div>
            <p class="hint">In ServiceNow, add <b>x-sn-apikey</b> as an HTTP header on your REST message.</p>
          </div>

          <!-- OAuth 2.0 -->
          <div class="tab-panel" data-panel-group="cred" id="cred-oauth" hidden>
            <div class="auth-row two">
              <div class="field">
                <label for="oauthGrant">Grant Type</label>
                <input type="text" id="oauthGrant" class="tag tag-violet" value="client_credentials" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="field">
                <label for="oauthUrlBox">Token URL</label>
                <div class="input-group">
                  <input type="text" id="oauthUrlBox" readonly spellcheck="false">
                  <button type="button" class="icon-btn" data-copy="oauthUrlBox" data-label="Token URL" title="Copy" aria-label="Copy token URL"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <div class="grid-2">
              <div class="field">
                <label for="oauthIdBox">Client ID</label>
                <div class="input-group">
                  <input type="text" id="oauthIdBox" readonly spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-copy="oauthIdBox" data-label="Client ID" title="Copy" aria-label="Copy client ID"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="field">
                <label for="oauthSecretBox">Client Secret</label>
                <div class="input-group">
                  <input type="password" id="oauthSecretBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-reveal="oauthSecretBox" title="Show / hide" aria-label="Show or hide client secret"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="oauthSecretBox" data-label="Client secret" title="Copy" aria-label="Copy client secret"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint">In ServiceNow, set Authentication type to <b>OAuth 2.0</b> pointing to this Token URL.</p>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>Quick Test cURL</h2><p>Ready-to-run cURL command for your selected auth method.</p></div>
          <button type="button" class="btn btn-secondary btn-sm" data-copy="curlBox" data-label="cURL command"><svg class="icon"><use href="#i-copy"/></svg>Copy</button>
        </div>
        <div class="card-body"><pre id="curlBox">Issuing credentials…</pre></div>
      </div>
    </section>

    <!-- Outbound -->
    <section id="panel-outbound" class="panel">
      <div class="card">
        <div class="card-head">
          <div><h2>ServiceNow Request Builder</h2><p>Execute authenticated requests against your PDI or ServiceNow tables with built-in templates.</p></div>
        </div>
        <div class="card-body">
          <!-- Quick Templates Bar -->
          <div class="templates-bar">
            <span style="font-size: 11.5px; font-weight: 700; color: var(--muted); align-self: center; text-transform: uppercase;">Templates:</span>
            <button type="button" class="template-chip" data-template="incident-post">+ Create Incident</button>
            <button type="button" class="template-chip" data-template="incident-get">+ Query Incidents</button>
            <button type="button" class="template-chip" data-template="user-get">+ Get Users</button>
            <button type="button" class="template-chip" data-template="ping">+ Health Check</button>
          </div>

          <div class="url-bar">
            <select id="httpMethod" aria-label="HTTP method">
              <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
            </select>
            <input type="url" id="httpUrl" placeholder="https://dev12345.service-now.com/api/now/table/incident" spellcheck="false" aria-label="Request URL">
            <button type="button" class="btn btn-primary" id="sendBtn"><svg class="icon"><use href="#i-send"/></svg>Send Request (Ctrl+Enter)</button>
          </div>

          <div class="seg" role="tablist" aria-label="Request sections">
            <button type="button" class="active" data-tab-group="pm" data-tab-target="pm-auth">Authorization</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-headers">Headers</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-body">Body</button>
          </div>

          <div class="tab-panel" data-panel-group="pm" id="pm-auth">
            <div class="field">
              <label for="authType">Auth Type</label>
              <select id="authType">
                <option value="basic">Basic Auth</option>
                <option value="bearer">Bearer Token (OAuth 2.0)</option>
                <option value="apikey">API Key (Custom Header)</option>
                <option value="none">No Auth</option>
              </select>
            </div>
            <div id="basicAuthFields" class="grid-2">
              <div class="field"><label for="basicUser">Username</label><input type="text" id="basicUser" placeholder="admin" autocomplete="off"></div>
              <div class="field">
                <label for="basicPass">Password</label>
                <div class="input-group">
                  <input type="password" id="basicPass" placeholder="Instance password" autocomplete="new-password">
                  <button type="button" class="icon-btn" data-reveal="basicPass" title="Show / hide" aria-label="Show or hide password"><svg class="icon"><use href="#i-eye"/></svg></button>
                </div>
              </div>
            </div>
            <div id="bearerAuthField" class="field" hidden>
              <label for="bearerToken">Access Token</label>
              <div class="input-group">
                <input type="password" id="bearerToken" placeholder="Paste OAuth bearer token" autocomplete="new-password">
                <button type="button" class="icon-btn" data-reveal="bearerToken" title="Show / hide" aria-label="Show or hide token"><svg class="icon"><use href="#i-eye"/></svg></button>
              </div>
            </div>
            <div id="apiKeyAuthFields" class="grid-2" hidden>
              <div class="field"><label for="apiKeyHeaderName">Header Name</label><input type="text" id="apiKeyHeaderName" value="x-sn-apikey" autocomplete="off"></div>
              <div class="field">
                <label for="apiKeyValue">API Key</label>
                <div class="input-group">
                  <input type="password" id="apiKeyValue" placeholder="Paste API key" autocomplete="new-password">
                  <button type="button" class="icon-btn" data-reveal="apiKeyValue" title="Show / hide" aria-label="Show or hide key"><svg class="icon"><use href="#i-eye"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint" id="hostHint">Requests are restricted to approved HTTPS ServiceNow hosts.</p>
          </div>

          <div class="tab-panel" data-panel-group="pm" id="pm-headers" hidden>
            <div id="headersList"></div>
            <button type="button" class="btn btn-secondary btn-sm" id="addHeaderBtn">+ Add Header</button>
          </div>

          <div class="tab-panel" data-panel-group="pm" id="pm-body" hidden>
            <label for="httpBody">Raw JSON Body</label>
            <textarea id="httpBody" rows="8" spellcheck="false">{
  "short_description": "Elite automated incident created via NexRelay Hub",
  "urgency": "2",
  "impact": "2",
  "category": "software"
}</textarea>
          </div>
        </div>
      </div>
    </section>

    <!-- Logs -->
    <section id="panel-logs" class="panel">
      <div class="toolbar">
        <div class="seg" role="tablist" aria-label="Filter logs" style="margin:0">
          <button type="button" class="active" data-filter="all">All Traffic</button>
          <button type="button" data-filter="inbound">Inbound</button>
          <button type="button" data-filter="outbound">Outbound</button>
        </div>
        <div class="spacer"></div>
        <button type="button" class="btn btn-danger-ghost btn-sm" id="clearAllBtn"><svg class="icon"><use href="#i-trash"/></svg>Delete All Records</button>
      </div>
      <div id="logsList"></div>
    </section>
  </main>
</div>

<div class="toasts" id="toasts" aria-live="polite"></div>

<div class="modal" id="modal" hidden>
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
    <h3 id="modalTitle"></h3>
    <p id="modalBody"></p>
    <div class="actions">
      <button type="button" class="btn btn-secondary" id="modalCancel">Cancel</button>
      <button type="button" class="btn btn-primary" id="modalConfirm">Confirm</button>
    </div>
  </div>
</div>

<script>
(function () {
  'use strict';

  var API = '/api/v1/servicenow';
  var DEVICE_RE = /^sn_dev_[a-f0-9]{48}$/;
  var MAX_RENDER_CHARS = 50000;
  var PAGES = {
    inbound: ['Inbound Webhook Hub', 'Receive ServiceNow payloads on a secured, secret-free workspace endpoint.'],
    outbound: ['Outbound HTTP Client', 'Send authenticated requests to your ServiceNow instance.'],
    logs: ['Execution Logs & Audit', 'Real-time audit trail of inbound and outbound traffic for this workspace.']
  };
  var state = { deviceId: '', creds: null, credTab: 'cred-bearer', seen: {}, primed: false, inbound: [], outbound: [], filter: 'all', sending: false, sig: '', open: {} };

  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v === undefined || v === null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function hex(n) {
    var a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  function formatTime(iso) {
    var d = new Date(iso);
    return isNaN(d) ? esc(iso) : esc(d.toLocaleString());
  }

  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || 'info');
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(function () { el.remove(); }, 3400);
  }

  var modalResolve = null;
  function confirmDialog(opts) {
    return new Promise(function (resolve) {
      $('modalTitle').textContent = opts.title;
      $('modalBody').textContent = opts.message;
      var ok = $('modalConfirm');
      ok.textContent = opts.confirmLabel || 'Confirm';
      ok.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');
      $('modal').hidden = false;
      $('modalCancel').focus();
      modalResolve = resolve;
    });
  }
  function closeModal(result) {
    $('modal').hidden = true;
    if (modalResolve) { var r = modalResolve; modalResolve = null; r(result); }
  }

  function fallbackCopy(v) {
    var t = document.createElement('textarea');
    t.value = v; t.setAttribute('readonly', '');
    t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.appendChild(t); t.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(t);
    return ok;
  }
  function copyText(value, label, btn) {
    if (!value) { toast('Nothing to copy yet', 'error'); return; }
    function done() { toast(label + ' copied to clipboard', 'success'); flashCopied(btn); }
    function fail() { toast('Copy failed', 'error'); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value) ? done() : fail(); });
    } else {
      fallbackCopy(value) ? done() : fail();
    }
  }

  function swapIcon(btn, id) {
    var u = btn.querySelector('use');
    if (u) u.setAttribute('href', '#' + id);
  }
  function flashCopied(btn) {
    if (!btn) return;
    var u = btn.querySelector('use');
    if (!u) return;
    if (!btn.getAttribute('data-orig')) btn.setAttribute('data-orig', u.getAttribute('href').slice(1));
    swapIcon(btn, 'i-check');
    setTimeout(function () { swapIcon(btn, btn.getAttribute('data-orig')); }, 1400);
  }

  function showPanel(name) {
    Array.prototype.forEach.call(document.querySelectorAll('.panel'), function (p) {
      p.classList.toggle('active', p.id === 'panel-' + name);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (b) {
      b.classList.toggle('active', b.getAttribute('data-panel') === name);
    });
    $('pageTitle').textContent = PAGES[name][0];
    $('pageSub').textContent = PAGES[name][1];
  }

  function switchTab(btn) {
    var group = btn.getAttribute('data-tab-group');
    var target = btn.getAttribute('data-tab-target');
    Array.prototype.forEach.call(document.querySelectorAll('[data-tab-group="' + group + '"]'), function (b) {
      b.classList.toggle('active', b === btn);
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-panel-group="' + group + '"]'), function (p) {
      p.hidden = p.id !== target;
    });
    if (group === 'cred') { state.credTab = target; renderCurl(); }
  }

  function getDeviceId() {
    var id = '';
    try { id = localStorage.getItem('nex_device_token') || ''; } catch (e) { id = ''; }
    if (!DEVICE_RE.test(id)) {
      id = 'sn_dev_' + hex(24);
      try { localStorage.setItem('nex_device_token', id); } catch (e) {}
    }
    return id;
  }

  function renderCredentials() {
    $('deviceIdBadge').textContent = state.deviceId.slice(0, 15) + '…';
    var base = location.origin + API;
    var url = base + '/inbound/' + state.deviceId;
    $('inboundUrlBox').value = url;
    $('oauthUrlBox').value = base + '/oauth/token/' + state.deviceId;
    var c = state.creds;
    if (!c) { renderCurl(); return; }
    $('bearerBox').value = c.bearer;
    $('basicUserBox').value = c.username;
    $('basicPassBox').value = c.password;
    $('apiKeyBox').value = c.apiKey;
    $('oauthIdBox').value = c.clientId;
    $('oauthSecretBox').value = c.clientSecret;
    if (c.allowedHosts && c.allowedHosts.length) {
      $('hostHint').textContent = 'Requests restricted to HTTPS hosts matching: ' + c.allowedHosts.join(', ') + '.';
    }
    renderCurl();
  }

  function renderCurl() {
    var box = $('curlBox');
    var c = state.creds;
    if (!c) { box.textContent = 'Issuing credentials…'; return; }
    var url = $('inboundUrlBox').value;
    var tail = "  -H 'Content-Type: application/json' \\\n" +
      "  -d '{\"short_description\":\"Test payload from NexRelay\"}'";
    var head = "curl -X POST '" + url + "' \\\n";
    var out;
    if (state.credTab === 'cred-basic') {
      out = head + "  -u '" + c.username + ":" + c.password + "' \\\n" + tail;
    } else if (state.credTab === 'cred-key') {
      out = head + "  -H 'x-sn-apikey: " + c.apiKey + "' \\\n" + tail;
    } else if (state.credTab === 'cred-oauth') {
      out = "# 1) Request an access token\n" +
        "curl -X POST '" + $('oauthUrlBox').value + "' \\\n" +
        "  -d 'grant_type=client_credentials' \\\n" +
        "  -d 'client_id=" + c.clientId + "' \\\n" +
        "  -d 'client_secret=" + c.clientSecret + "'\n\n" +
        "# 2) Call webhook with returned access_token\n" +
        head + "  -H 'Authorization: Bearer <access_token>' \\\n" + tail;
    } else {
      out = head + "  -H 'Authorization: Bearer " + c.bearer + "' \\\n" + tail;
    }
    box.textContent = out;
  }

  function rotateCredentials(manual) {
    return fetch(API + '/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: state.deviceId })
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (c) {
      state.creds = c;
      renderCredentials();
      if (manual) toast('New credentials issued. Previous ones revoked.', 'success');
    }).catch(function (e) {
      toast('Could not issue credentials: ' + e.message, 'error');
    });
  }

  function signature(inb, out) {
    return (inb[0] ? inb[0].id : '') + '|' + (out[0] ? out[0].id : '') + '|' + inb.length + '|' + out.length;
  }

  function updateMetrics() {
    var all = state.outbound.concat(state.inbound);
    var total = all.length;
    $('metricTotal').textContent = total;

    var successes = state.outbound.filter(function(o) { return o.statusCode >= 200 && o.statusCode < 300; }).length;
    var outboundTotal = state.outbound.length;
    var successRate = outboundTotal > 0 ? Math.round((successes / outboundTotal) * 100) : 100;
    $('metricSuccess').textContent = successRate + '%';

    var totalLatency = state.outbound.reduce(function(acc, o) { return acc + (o.durationMs || 0); }, 0);
    var avgLatency = outboundTotal > 0 ? Math.round(totalLatency / outboundTotal) : 0;
    $('metricLatency').textContent = avgLatency + ' ms';
  }

  function loadLogs() {
    if (document.hidden || !state.deviceId) return;
    fetch(API + '/logs', { headers: { 'X-Device-Token': state.deviceId }, cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || !d.inbound || !d.outbound) return;
        var s = signature(d.inbound, d.outbound);
        if (s === state.sig) return;
        state.sig = s; state.inbound = d.inbound; state.outbound = d.outbound;
        if (!state.primed) {
          state.primed = true;
          d.inbound.concat(d.outbound).forEach(function (i) { state.seen[i.id] = true; });
        }
        renderLogs();
        updateMetrics();
      }).catch(function () {});
  }

  function badge(text, cls) { return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }

  function block(label, data) {
    if (data === null || data === undefined || data === '') return '';
    var text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    var cut = false;
    if (text.length > MAX_RENDER_CHARS) { text = text.slice(0, MAX_RENDER_CHARS); cut = true; }
    return '<div class="block"><div class="block-label">' + esc(label) + '</div><pre>' + esc(text) + '</pre>' +
      (cut ? '<div class="trunc">Output truncated.</div>' : '') + '</div>';
  }

  function logCard(item) {
    var inbound = item.direction === 'INBOUND';
    var delBtn = '<button type="button" class="btn btn-danger-ghost btn-sm" data-delete="' + esc(item.id) + '">' +
      '<svg class="icon"><use href="#i-trash"/></svg>Delete</button>';
    var head, body;
    if (inbound) {
      head = badge('Inbound', 'b-info') + badge(item.authMethod || 'Authenticated', 'b-ok') + '<span class="log-id">' + esc(item.id) + '</span>';
      body = block('Payload', item.payload);
    } else {
      var code = item.statusCode || 0;
      var cls = code >= 200 && code < 300 ? 'b-ok' : (code >= 300 && code < 400 ? 'b-warn' : 'b-err');
      head = badge(item.method, 'b-neutral') + badge(item.status, cls) + '<span class="log-id">' + esc(item.id) + '</span>' +
        '<span class="log-meta">' + esc(item.durationMs) + ' ms</span>';
      body = block('Request body', item.requestPayload) + block('Response', item.responsePayload);
    }
    var open = state.open[item.id] ? ' open' : '';
    return '<article class="log" data-card="' + esc(item.id) + '">' +
      '<div class="log-head"><div class="log-title">' + head + '</div>' +
      '<div class="log-actions"><span class="log-meta">' + formatTime(item.timestamp) + '</span>' + delBtn + '</div></div>' +
      (inbound ? '' : '<div class="log-url">' + esc(item.url) + '</div>') +
      (body ? '<details data-id="' + esc(item.id) + '"' + open + '><summary>' + (inbound ? 'Payload' : 'Request &amp; Response') + '</summary>' + body + '</details>' : '') +
      '</article>';
  }

  function renderLogs() {
    var all = state.outbound.concat(state.inbound).sort(function (a, b) {
      return new Date(b.timestamp) - new Date(a.timestamp);
    });
    $('logCount').textContent = all.length;
    $('clearAllBtn').disabled = all.length === 0;

    var list = all.filter(function (i) {
      return state.filter === 'all' || i.direction.toLowerCase() === state.filter;
    });
    if (!list.length) {
      $('logsList').innerHTML = '<div class="empty"><svg class="icon"><use href="#i-list"/></svg>' +
        '<strong>No records to show</strong><span>Inbound webhooks and outbound requests will appear here.</span></div>';
      return;
    }
    $('logsList').innerHTML = list.map(logCard).join('');
    all.forEach(function (i) { state.seen[i.id] = true; });
  }

  function resetSignature() {
    state.sig = signature(state.inbound, state.outbound);
  }

  function deleteRecord(id) {
    confirmDialog({
      title: 'Delete record?',
      message: 'Record ' + id + ' will be permanently removed from this workspace.',
      confirmLabel: 'Delete record', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs/' + encodeURIComponent(id), { method: 'DELETE', headers: { 'X-Device-Token': state.deviceId } })
        .then(function (r) {
          if (r.ok) {
            state.inbound = state.inbound.filter(function (i) { return i.id !== id; });
            state.outbound = state.outbound.filter(function (i) { return i.id !== id; });
            delete state.open[id];
            resetSignature(); renderLogs(); updateMetrics();
            toast('Record ' + id + ' deleted', 'success');
          }
        });
    });
  }

  function deleteAll() {
    var total = state.inbound.length + state.outbound.length;
    if (!total) { toast('No records to delete', 'info'); return; }
    confirmDialog({
      title: 'Delete all records?',
      message: 'All ' + total + ' records in this workspace will be permanently deleted.',
      confirmLabel: 'Delete all', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs', { method: 'DELETE', headers: { 'X-Device-Token': state.deviceId } })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
        .then(function (d) {
          state.inbound = []; state.outbound = []; state.open = {};
          resetSignature(); renderLogs(); updateMetrics();
          toast(d.deleted + ' records deleted', 'success');
        });
    });
  }

  function addHeaderRow(k, v) {
    var row = document.createElement('div');
    row.className = 'header-row';
    row.innerHTML = '<input type="text" class="h-key" placeholder="Header name" aria-label="Header name">' +
      '<input type="text" class="h-val" placeholder="Value" aria-label="Header value">' +
      '<button type="button" class="icon-btn" data-remove-row title="Remove header" aria-label="Remove header"><svg class="icon"><use href="#i-trash"/></svg></button>';
    row.querySelector('.h-key').value = k || '';
    row.querySelector('.h-val').value = v || '';
    $('headersList').appendChild(row);
  }

  function updateAuthFields() {
    var t = $('authType').value;
    $('basicAuthFields').hidden = t !== 'basic';
    $('bearerAuthField').hidden = t !== 'bearer';
    $('apiKeyAuthFields').hidden = t !== 'apikey';
  }

  function updateBodyState() {
    var m = $('httpMethod').value;
    $('httpBody').disabled = (m === 'GET' || m === 'DELETE');
  }

  // Quick Action Templates for ServiceNow Developers
  function loadTemplate(type) {
    var urlInput = $('httpUrl');
    var methodInput = $('httpMethod');
    var bodyInput = $('httpBody');
    
    if (type === 'incident-post') {
      methodInput.value = 'POST';
      urlInput.value = 'https://dev_instance.service-now.com/api/now/table/incident';
      bodyInput.value = JSON.stringify({
        short_description: "Automated test incident from NexRelay Enterprise",
        urgency: "2",
        impact: "2",
        category: "hardware"
      }, null, 2);
    } else if (type === 'incident-get') {
      methodInput.value = 'GET';
      urlInput.value = 'https://dev_instance.service-now.com/api/now/table/incident?sysparm_limit=5&sysparm_display_value=true';
      bodyInput.value = '';
    } else if (type === 'user-get') {
      methodInput.value = 'GET';
      urlInput.value = 'https://dev_instance.service-now.com/api/now/table/sys_user?sysparm_limit=10';
      bodyInput.value = '';
    } else if (type === 'ping') {
      methodInput.value = 'GET';
      urlInput.value = location.origin + '/health';
      bodyInput.value = '';
    }
    updateBodyState();
    toast('Template loaded successfully', 'success');
  }

  function sendOutbound() {
    if (state.sending) return;
    var url = $('httpUrl').value.trim();
    if (!url) { toast('Enter a target ServiceNow endpoint URL', 'error'); return; }

    var method = $('httpMethod').value;
    var rawBody = $('httpBody').value;
    var headers = {};
    Array.prototype.forEach.call(document.querySelectorAll('#headersList .header-row'), function (row) {
      var k = row.querySelector('.h-key').value.trim();
      var v = row.querySelector('.h-val').value.trim();
      if (k) headers[k] = v;
    });

    var parsed = null;
    if (['POST', 'PUT', 'PATCH'].indexOf(method) > -1 && rawBody.trim()) {
      try { parsed = JSON.parse(rawBody); }
      catch (e) { toast('Invalid JSON body syntax', 'error'); return; }
    }

    state.sending = true;
    var btn = $('sendBtn');
    btn.disabled = true;

    fetch(API + '/outbound', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Device-Token': state.deviceId },
      body: JSON.stringify({
        method: method, url: url, authType: $('authType').value,
        basicUser: $('basicUser').value, basicPass: $('basicPass').value,
        bearerToken: $('bearerToken').value,
        apiKeyHeaderName: $('apiKeyHeaderName').value, apiKeyValue: $('apiKeyValue').value,
        headers: headers, body: parsed
      })
    }).then(function (res) {
      return res.json().then(function (data) { return { ok: res.ok, data: data }; });
    }).then(function (r) {
      if (r.ok && r.data.record) {
        state.outbound.unshift(r.data.record);
        resetSignature(); renderLogs(); updateMetrics();
        var rec = r.data.record;
        toast(rec.method + ' completed: ' + rec.status, rec.statusCode >= 200 && rec.statusCode < 300 ? 'success' : 'error');
        showPanel('logs');
      } else {
        toast((r.data && r.data.message) || 'Request failed', 'error');
      }
    }).catch(function () {
      toast('Could not reach the gateway', 'error');
    }).then(function () {
      state.sending = false;
      btn.disabled = false;
    });
  }

  function setStatus(ok) {
    var pill = $('statusPill');
    pill.classList.toggle('ok', ok);
    pill.classList.toggle('bad', !ok);
    $('statusText').textContent = ok ? 'Gateway online' : 'Gateway unreachable';
  }
  function checkHealth() {
    fetch('/health', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function () { setStatus(true); }, function () { setStatus(false); });
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    var el;

    if ((el = t.closest('[data-template]'))) {
      loadTemplate(el.getAttribute('data-template'));
      return;
    }
    if ((el = t.closest('[data-copy-header]'))) {
      if (!state.creds) { toast('Credentials still issuing', 'error'); return; }
      copyText('Bearer ' + state.creds.bearer, 'Authorization header value', el);
      return;
    }
    if ((el = t.closest('[data-copy]'))) {
      var src = $(el.getAttribute('data-copy'));
      var val = (src.value !== undefined) ? src.value : src.textContent;
      copyText(val, el.getAttribute('data-label') || 'Value', el);
      return;
    }
    if ((el = t.closest('[data-reveal]'))) {
      var f = $(el.getAttribute('data-reveal'));
      var show = f.type === 'password';
      f.type = show ? 'text' : 'password';
      swapIcon(el, show ? 'i-eye-off' : 'i-eye');
      return;
    }
    if ((el = t.closest('[data-tab-group]'))) { switchTab(el); return; }
    if ((el = t.closest('[data-panel]'))) { showPanel(el.getAttribute('data-panel')); return; }
    if ((el = t.closest('[data-filter]'))) {
      state.filter = el.getAttribute('data-filter');
      Array.prototype.forEach.call(document.querySelectorAll('[data-filter]'), function (b) { b.classList.toggle('active', b === el); });
      renderLogs();
      return;
    }
    if ((el = t.closest('[data-delete]'))) { deleteRecord(el.getAttribute('data-delete')); return; }
    if ((el = t.closest('[data-remove-row]'))) { el.parentElement.remove(); return; }
  });

  document.addEventListener('toggle', function (e) {
    var d = e.target;
    if (d && d.matches && d.matches('details[data-id]')) state.open[d.getAttribute('data-id')] = d.open;
  }, true);

  // Keyboard shortcuts (Ctrl + Enter to send request)
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      var outboundPanel = $('panel-outbound');
      if (outboundPanel.classList.contains('active')) {
        e.preventDefault();
        sendOutbound();
      }
    }
  });

  $('modalConfirm').addEventListener('click', function () { closeModal(true); });
  $('modalCancel').addEventListener('click', function () { closeModal(false); });

  $('rotateBtn').addEventListener('click', function () { rotateCredentials(true); });
  $('clearAllBtn').addEventListener('click', deleteAll);
  $('sendBtn').addEventListener('click', sendOutbound);
  $('addHeaderBtn').addEventListener('click', function () { addHeaderRow('', ''); });
  $('authType').addEventListener('change', updateAuthFields);
  $('httpMethod').addEventListener('change', updateBodyState);

  $('newSessionBtn').addEventListener('click', function () {
    confirmDialog({
      title: 'Start a new workspace?',
      message: 'You will get a new endpoint URL and an empty log history.',
      confirmLabel: 'Create workspace'
    }).then(function (yes) {
      if (!yes) return;
      state.deviceId = 'sn_dev_' + hex(24);
      try { localStorage.setItem('nex_device_token', state.deviceId); } catch (e) {}
      state.creds = null; state.inbound = []; state.outbound = []; state.open = {}; state.sig = '';
      renderCredentials(); renderLogs(); updateMetrics();
      rotateCredentials(false).then(function () { toast('New workspace created', 'success'); });
    });
  });

  state.deviceId = getDeviceId();
  addHeaderRow('Accept', 'application/json');
  updateAuthFields();
  updateBodyState();
  showPanel('inbound');
  renderCredentials();
  renderLogs();
  updateMetrics();
  rotateCredentials(false);
  loadLogs();
  checkHealth();
  setInterval(loadLogs, 3000);
  setInterval(checkHealth, 30000);
})();
</script>
</body>
</html>`;

app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.type('html').send(PAGE);
});

app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({
            status: 'Error',
            message: 'Invalid JSON body. Send valid JSON with the header Content-Type: application/json.'
        });
    }
    console.error(err);
    res.status(500).json({ status: 'Error', message: 'Internal server error.' });
});

app.listen(PORT, () => {
    console.log(`NexRelay Enterprise Edition running on port ${PORT}`);
});