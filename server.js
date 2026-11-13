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
const BASIC_USERNAME = process.env.BASIC_USERNAME || 'nexrelay_admin'; // permanent username
const INBOUND_TOKEN = process.env.INBOUND_TOKEN || '';
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '.service-now.com')
    .split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
const OUTBOUND_TIMEOUT_MS = 30000;
const OAUTH_TOKEN_TTL_S = Number(process.env.OAUTH_TOKEN_TTL_S) || 3600; // lifetime of OAuth access tokens issued by the hub
const OAUTH_MAX_TOKENS = 20;      // live tokens kept per workspace
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
app.use(bodyParser.urlencoded({ extended: false, limit: '20kb' })); // OAuth token requests are form-encoded

// ---- Stores ----
// deviceStores: { [deviceId]: { inbound: [], outbound: [] } }
// sessions:     { [deviceId]: { bearer, apiKey, password } }  (SHA-256 digests only)
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
        if (matches(candidate, t.digest)) ok = true; // no early exit: constant work per token
    }
    return ok;
}

// Returns the name of the method that authenticated the request, or null.
// Supported: Bearer token, Basic auth, API key (header or query string), OAuth 2.0 client-credentials access token.
function authenticateInbound(req, session) {
    const auth = req.headers['authorization'] || '';
    const headerKey = req.headers['x-sn-apikey'] || req.headers['x-api-key'] || '';
    const queryKey = typeof req.query.api_key === 'string' ? req.query.api_key : '';

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
    if (queryKey && matches(queryKey, session.apiKey)) return 'API Key (Query)';
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

// 0. Credential issuing: a brand-new random key, token and password on every call (page load)
app.post('/api/v1/servicenow/session', (req, res) => {
    const deviceId = String((req.body && req.body.deviceId) || '');
    if (!DEVICE_ID_RE.test(deviceId)) {
        return res.status(400).json({ status: 'Error', message: 'Invalid deviceId.' });
    }
    const creds = {
        username: BASIC_USERNAME,                              // permanent
        clientId: 'nexrelay_' + deviceId.slice(7, 19),         // stable per workspace
        password: randomSecret('sn_pass_', 16),                // rotates
        apiKey: randomSecret('sn_key_', 20),                   // rotates
        bearer: randomSecret('sn_nex_', 24),                   // rotates
        clientSecret: randomSecret('sn_sec_', 24)              // rotates
    };
    // Replacing the record also revokes every OAuth access token issued earlier.
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

// 0b. OAuth 2.0 token endpoint (client_credentials grant) - what ServiceNow's OAuth profile calls
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

    // Client credentials may arrive in the form body or as HTTP Basic (client_id:client_secret)
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
        return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client or wrong secret. Credentials rotate on every page load.' });
    }

    const accessToken = randomSecret('sn_oat_', 24);
    session.tokens = session.tokens
        .filter(t => t.exp > Date.now())
        .concat({ digest: digest(accessToken), exp: Date.now() + OAUTH_TOKEN_TTL_S * 1000 })
        .slice(-OAUTH_MAX_TOKENS);
    console.log(`[ServiceNow OAuth] Device: ${id} | access token issued`);

    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: OAUTH_TOKEN_TTL_S });
});

// 1. ServiceNow Inbound REST Endpoint (workspace-scoped URL; credentials are always enforced)
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
            message: 'Authentication failed: use the current Bearer token, Basic credentials, API key or OAuth 2.0 access token shown in the hub. Credentials rotate on every page load.'
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
    console.log(`[ServiceNow Inbound] Device: ${requested || 'Global'} | ID: ${syncId} | ${authMethod}`);

    res.status(200).json({
        status: 'Success',
        message: 'Inbound ServiceNow payload successfully ingested into device session.',
        record: inboundEntry
    });
});

// 2. Outbound HTTP Proxy (isolated per device, restricted to allowed hosts)
app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);

    const { method, url, authType, basicUser, basicPass, bearerToken, apiKeyHeaderName, apiKeyValue, headers, body } = req.body || {};

    if (!url || !method) {
        return res.status(400).json({
            status: 'Error',
            message: 'Validation Error: Both HTTP Method and Target Endpoint URL are required to execute the request.'
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
            diagnosticAdvice: 'Verify that your ServiceNow Personal Developer Instance (PDI) is online and reachable.'
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
    console.log(`[ServiceNow Outbound] Device: ${deviceId} | ${fetchOptions.method} ${url} -> ${responseStatus}`);

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

// Delete ALL records for this device
app.delete('/api/v1/servicenow/logs', (req, res) => {
    const deviceId = deviceFrom(req, res);
    if (!deviceId) return;
    const store = getStore(deviceId);
    const deleted = store.inbound.length + store.outbound.length;
    store.inbound = [];
    store.outbound = [];
    res.json({ status: 'Cleared', deleted });
});

// Delete ONE record
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

// 3. Frontend
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexRelay · ServiceNow Integration Hub</title>
<style>
:root{
  --bg:#f3f5f8;--surface:#ffffff;--surface-2:#f8fafc;--border:#e3e8ef;--border-strong:#cbd5e1;
  --text:#0f172a;--muted:#64748b;--accent:#0a7d5c;--accent-hover:#086a4e;--accent-ink:#ffffff;--accent-soft:#e6f4ef;
  --danger:#dc2626;--danger-hover:#b91c1c;--danger-soft:#fef2f2;--ok:#15803d;--ok-soft:#ecfdf3;
  --warn:#b45309;--warn-soft:#fffbeb;--info:#1d4ed8;--info-soft:#eff6ff;
  --side:#0b1a1f;--side-text:#9fb3b8;--side-active:#12302f;
  --shadow:0 1px 2px rgba(15,23,42,.05),0 1px 3px rgba(15,23,42,.08);
  --shadow-lg:0 20px 40px rgba(15,23,42,.22);
  --blue:#1a56db;--blue-bg:#e8f0fe;--blue-bd:#bcd0fb;
  --violet:#6d28d9;--violet-bg:#f1e9ff;--violet-bd:#d9c6fb;
  --amber:#b45309;--amber-bg:#fff4e0;--amber-bd:#f6d9a6;
  --green:#0a7d5c;--green-bg:#e6f4ef;--green-bd:#bfe3d4;
  --rose:#be123c;--rose-bg:#ffe9ee;--rose-bd:#f8c3cf;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0b1115;--surface:#111a20;--surface-2:#0d161b;--border:#1f2c34;--border-strong:#2c3c47;
    --text:#e6edf3;--muted:#8b9db0;--accent:#2dbd8c;--accent-hover:#25a47a;--accent-ink:#04130d;--accent-soft:#0f2b25;
    --danger:#f87171;--danger-hover:#ef4444;--danger-soft:#2a1416;--ok:#4ade80;--ok-soft:#0f2a1a;
    --warn:#fbbf24;--warn-soft:#2b210d;--info:#60a5fa;--info-soft:#0f1d33;
    --side:#080f13;--side-active:#102a2a;--shadow:0 1px 2px rgba(0,0,0,.4);--shadow-lg:0 20px 40px rgba(0,0,0,.6);
    --blue:#7fb0ff;--blue-bg:#11223f;--blue-bd:#1d3a6b;
    --violet:#b79cff;--violet-bg:#231a3d;--violet-bd:#3a2c63;
    --amber:#fbbf24;--amber-bg:#2b210d;--amber-bd:#4a3a14;
    --green:#4ade80;--green-bg:#0f2b25;--green-bd:#1d4a3c;
    --rose:#fb7185;--rose-bg:#2c121a;--rose-bd:#52202c;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
[hidden]{display:none!important}
button{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

.app{display:grid;grid-template-columns:256px minmax(0,1fr);min-height:100vh}
.sidebar{background:var(--side);color:var(--side-text);display:flex;flex-direction:column;padding:20px 14px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:12px;padding:4px 8px 24px}
.brand-mark{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#0a7d5c,#2dbd8c);display:grid;place-items:center;color:#fff}
.brand-mark .icon{width:20px;height:20px}
.brand strong{display:block;color:#fff;font-size:15px;letter-spacing:.2px}
.brand span{font-size:12px}
.nav{display:flex;flex-direction:column;gap:4px}
.nav-label{font-size:11px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;padding:0 12px 8px;color:#6b8288}
.nav-item{display:flex;align-items:center;gap:12px;width:100%;padding:10px 12px;border:0;border-radius:8px;background:transparent;color:var(--side-text);font-weight:500;text-align:left;cursor:pointer;transition:background .15s,color .15s}
.nav-item:hover{background:rgba(255,255,255,.05);color:#fff}
.nav-item.active{background:var(--side-active);color:#fff;box-shadow:inset 3px 0 0 var(--accent)}
.count{margin-left:auto;min-width:22px;padding:1px 7px;border-radius:999px;background:rgba(255,255,255,.12);color:#fff;font-size:11px;font-weight:600;text-align:center}
.side-foot{margin-top:auto;padding:14px 12px 0;border-top:1px solid rgba(255,255,255,.08);font-size:12px}
.side-foot .lbl{text-transform:uppercase;letter-spacing:.8px;font-size:10px;color:#6b8288;margin-bottom:4px}
.side-foot code{display:block;color:#cfe0e3;font-family:var(--mono);margin-bottom:12px}
.btn-side{width:100%;padding:8px 10px;border-radius:8px;border:1px solid rgba(255,255,255,.14);background:transparent;color:#cfe0e3;cursor:pointer;font-weight:500}
.btn-side:hover{background:rgba(255,255,255,.07);color:#fff}

.main{padding:28px 36px 56px;width:100%;max-width:1180px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:24px}
.topbar h1{margin:0;font-size:22px;font-weight:650;letter-spacing:-.2px}
.topbar p{margin:4px 0 0;color:var(--muted)}
.status{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:12px;font-weight:600;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.status.ok .dot{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.status.bad .dot{background:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}

.panel{display:none}
.panel.active{display:block;animation:rise .25s ease}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);margin-bottom:20px}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 22px;border-bottom:1px solid var(--border)}
.card-head h2{margin:0;font-size:15px;font-weight:600}
.card-head p{margin:2px 0 0;color:var(--muted);font-size:13px}
.card-body{padding:22px}

label{display:block;margin-bottom:6px;font-size:12px;font-weight:600;color:var(--muted);letter-spacing:.2px}
.field{margin-bottom:18px}
.field:last-child{margin-bottom:0}
input,select,textarea{width:100%;background:var(--surface);color:var(--text);border:1px solid var(--border-strong);border-radius:8px;padding:9px 12px;font:inherit}
textarea{font-family:var(--mono);font-size:12.5px;resize:vertical;min-height:140px}
textarea:disabled{opacity:.55}
input::placeholder,textarea::placeholder{color:var(--muted);opacity:.7}
.input-group{display:flex;align-items:stretch;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface-2);overflow:hidden}
.input-group:focus-within{outline:2px solid var(--accent);outline-offset:1px}
.input-group input{border:0;background:transparent;border-radius:0;font-family:var(--mono);font-size:13px}
.input-group input:focus-visible{outline:none}
.icon-btn{display:inline-grid;place-items:center;width:40px;flex:none;border:0;border-left:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;transition:background .15s,color .15s}
.icon-btn:hover{background:var(--accent-soft);color:var(--accent)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 16px;border-radius:8px;border:1px solid transparent;font-weight:600;cursor:pointer;white-space:nowrap;transition:background .15s,border-color .15s,color .15s}
.btn:disabled{opacity:.55;cursor:not-allowed}
.btn-sm{padding:6px 12px;font-size:13px}
.btn-primary{background:var(--accent);color:var(--accent-ink)}
.btn-primary:hover:not(:disabled){background:var(--accent-hover)}
.btn-secondary{background:var(--surface);color:var(--text);border-color:var(--border-strong)}
.btn-secondary:hover:not(:disabled){background:var(--surface-2)}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover:not(:disabled){background:var(--danger-hover)}
.btn-danger-ghost{background:transparent;color:var(--danger);border-color:var(--border-strong)}
.btn-danger-ghost:hover:not(:disabled){background:var(--danger-soft);border-color:var(--danger)}

.seg{display:inline-flex;padding:3px;gap:2px;background:var(--surface-2);border:1px solid var(--border);border-radius:9px;margin-bottom:20px}
.seg button{border:0;background:transparent;padding:6px 14px;border-radius:7px;font-weight:500;color:var(--muted);cursor:pointer}
.seg button:hover{color:var(--text)}
.seg button.active{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}

.url-bar{display:grid;grid-template-columns:120px minmax(0,1fr) auto;gap:10px;margin-bottom:22px}
.url-bar select{font-weight:700}
.url-bar input{font-family:var(--mono);font-size:13px}
.header-row{display:grid;grid-template-columns:1fr 1fr 40px;gap:10px;margin-bottom:10px}
.header-row .icon-btn{border:1px solid var(--border-strong);border-radius:8px}
.hint{margin:10px 0 0;color:var(--muted);font-size:12px}
.hint b{color:var(--text);font-weight:600}

/* Read-only, colour-coded header/scheme/parameter names (kept separate from the secret itself) */
.tag{font-family:var(--mono);font-weight:700;font-size:13px;letter-spacing:.2px;text-align:center;cursor:default;border:1px solid;user-select:all}
.tag-blue{color:var(--blue);background:var(--blue-bg);border-color:var(--blue-bd)}
.tag-violet{color:var(--violet);background:var(--violet-bg);border-color:var(--violet-bd)}
.tag-amber{color:var(--amber);background:var(--amber-bg);border-color:var(--amber-bd)}
.tag-green{color:var(--green);background:var(--green-bg);border-color:var(--green-bd)}
.tag-rose{color:var(--rose);background:var(--rose-bg);border-color:var(--rose-bd)}
.auth-row{display:grid;grid-template-columns:170px 120px minmax(0,1fr);gap:12px;align-items:end;margin-bottom:14px}
.auth-row.two{grid-template-columns:170px minmax(0,1fr)}
.auth-row.opt{grid-template-columns:130px 170px minmax(0,1fr)}
.auth-row .field{margin-bottom:0}
.note-cell{padding:9px 0;color:var(--muted);font-size:13px}
.note-cell code{font-family:var(--mono);color:var(--text)}
.opt-title{margin:22px 0 10px;font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--muted)}
.panel-actions{margin:2px 0 4px}
@media (max-width:900px){.auth-row,.auth-row.two,.auth-row.opt{grid-template-columns:1fr}}

.note{display:flex;gap:10px;align-items:flex-start;padding:10px 14px;border-radius:8px;background:var(--warn-soft);color:var(--warn);font-size:13px;margin-bottom:20px}

.toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.toolbar .seg{margin:0}
.spacer{flex:1}
.log{background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);margin-bottom:14px;overflow:hidden}
.log-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px 18px}
.log-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}
.log-id{font-family:var(--mono);font-size:12.5px;font-weight:600}
.log-meta{color:var(--muted);font-size:12px}
.log-actions{display:flex;align-items:center;gap:12px}
.log-url{padding:0 18px 12px;font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all}
.log details{border-top:1px solid var(--border)}
.log summary{padding:10px 18px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;user-select:none}
.log summary:hover{color:var(--text)}
.block{padding:0 18px 16px}
.block-label{margin-bottom:6px;font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--muted)}
pre{margin:0;padding:14px 16px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px;font:12px/1.55 var(--mono);overflow:auto;max-height:360px;white-space:pre-wrap;word-break:break-word}
.trunc{margin-top:6px;font-size:12px;color:var(--warn)}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.2px}
.b-info{background:var(--info-soft);color:var(--info)}
.b-ok{background:var(--ok-soft);color:var(--ok)}
.b-warn{background:var(--warn-soft);color:var(--warn)}
.b-err{background:var(--danger-soft);color:var(--danger)}
.b-neutral{background:var(--surface-2);color:var(--muted);border:1px solid var(--border)}
.empty{display:grid;place-items:center;gap:8px;text-align:center;padding:56px 20px;border:1px dashed var(--border-strong);border-radius:12px;color:var(--muted);background:var(--surface)}
.empty .icon{width:28px;height:28px}
.empty strong{color:var(--text)}

.toasts{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;z-index:60}
.toast{min-width:240px;max-width:380px;padding:12px 16px;border-radius:10px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--info);box-shadow:var(--shadow-lg);font-size:13px;animation:rise .2s ease}
.toast.success{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--danger)}
.toast.out{opacity:0;transform:translateY(6px);transition:all .25s}
.modal{position:fixed;inset:0;background:rgba(2,8,12,.6);display:grid;place-items:center;padding:20px;z-index:80}
.dialog{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px;box-shadow:var(--shadow-lg)}
.dialog h3{margin:0 0 8px;font-size:16px}
.dialog p{margin:0 0 22px;color:var(--muted)}
.dialog .actions{display:flex;justify-content:flex-end;gap:10px}

@media (max-width:900px){
  .app{grid-template-columns:1fr}
  .sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 14px}
  .brand{padding:0 8px 0 0}.nav-label,.side-foot{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .main{padding:20px 16px 48px}
  .grid-2,.url-bar{grid-template-columns:1fr}
  .topbar{flex-direction:column}
}
/* ===== Motion: transform/opacity only, no continuous JS loops ===== */
:root{--ease:cubic-bezier(.2,.8,.2,1)}
@keyframes enter{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes navIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:none}}
@keyframes tabIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes toastIn{from{opacity:0;transform:translateX(28px) scale(.98)}to{opacity:1;transform:none}}
@keyframes bar{to{transform:scaleX(0)}}
@keyframes ping{75%,100%{transform:scale(2.6);opacity:0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes flash{from{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}to{border-color:var(--border-strong);box-shadow:0 0 0 0 transparent}}
@keyframes sheen{to{transform:translateX(100%)}}
@keyframes bump{0%{transform:scale(1)}40%{transform:scale(1.3)}100%{transform:scale(1)}}
@keyframes pop{0%{transform:scale(.55)}60%{transform:scale(1.2)}100%{transform:scale(1)}}
@keyframes logIn{from{opacity:0;transform:translateY(-12px) scale(.985);border-color:var(--accent)}to{opacity:1;transform:none;border-color:var(--border)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes fadeOut{from{opacity:1}to{opacity:0}}
@keyframes dialogIn{from{opacity:0;transform:translateY(14px) scale(.94)}to{opacity:1;transform:none}}
@keyframes dialogOut{from{opacity:1;transform:none}to{opacity:0;transform:translateY(8px) scale(.97)}}

/* page + panel entrances (staggered) */
.topbar{animation:enter .5s var(--ease) backwards}
.panel.active{animation:none}
.panel.active>*{animation:enter .5s var(--ease) backwards}
.panel.active>*:nth-child(2){animation-delay:.06s}
.panel.active>*:nth-child(3){animation-delay:.12s}
.panel.active>*:nth-child(4){animation-delay:.18s}
.nav-item{animation:navIn .5s var(--ease) backwards}
.nav-item:nth-child(3){animation-delay:.05s}
.nav-item:nth-child(4){animation-delay:.1s}
.tab-panel:not([hidden]){animation:tabIn .32s var(--ease)}

/* sidebar: sliding active indicator */
.nav{position:relative}
.nav-indicator{position:absolute;left:0;top:0;border-radius:8px;background:var(--side-active);box-shadow:inset 3px 0 0 var(--accent);pointer-events:none;z-index:0;transition:transform .38s var(--ease),width .38s var(--ease),height .38s var(--ease)}
.nav-item{position:relative;z-index:1}
.nav-item.active,.nav-item.active:hover{background:transparent;box-shadow:none}
.nav-item .icon{transition:transform .25s var(--ease)}
.nav-item:hover .icon{transform:translateX(3px)}
.brand-mark{transition:transform .4s var(--ease)}
.brand:hover .brand-mark{transform:rotate(-8deg) scale(1.06)}

/* segmented controls: sliding thumb */
.seg{position:relative}
.seg button{position:relative;z-index:1;transition:color .2s}
.seg button.active{background:transparent;box-shadow:none}
.seg-thumb{position:absolute;left:0;top:0;width:0;height:0;border-radius:7px;background:var(--surface);box-shadow:var(--shadow);pointer-events:none;z-index:0;transition:transform .38s var(--ease),width .38s var(--ease),height .38s var(--ease)}

/* buttons, cards, inputs */
.btn{transition:background .15s,border-color .15s,color .15s,transform .12s,box-shadow .2s}
.btn:active:not(:disabled){transform:scale(.97)}
.btn-primary:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 16px rgba(10,125,92,.28)}
.btn.loading{pointer-events:none}
.btn.loading .icon{display:none}
.btn.loading::before{content:'';width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
.btn.busy .icon{animation:spin .8s linear infinite}
.card{transition:box-shadow .25s,border-color .25s}
.card:hover{box-shadow:0 8px 24px rgba(15,23,42,.08);border-color:var(--border-strong)}
.input-group{position:relative;transition:border-color .2s,box-shadow .2s}
.input-group:focus-within{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.icon-btn{transition:background .15s,color .15s}
.icon-btn:active{transform:scale(.92)}
.icon-btn.pop .icon,.btn.pop .icon{animation:pop .35s var(--ease)}
.icon-btn.copied{color:var(--ok);background:var(--ok-soft)}
.btn.copied{color:var(--ok);border-color:var(--ok)}
.input-group.shimmer::after{content:'';position:absolute;inset:0;background:linear-gradient(100deg,transparent 30%,var(--accent-soft) 50%,transparent 70%);transform:translateX(-100%);animation:sheen 1.2s infinite;pointer-events:none}
.input-group.flash{animation:flash 1s ease}

/* status, counts, empty state */
.status.ok .dot{position:relative}
.status.ok .dot::after{content:'';position:absolute;inset:0;border-radius:50%;background:var(--ok);animation:ping 2s cubic-bezier(0,0,.2,1) infinite}
.count.bump{animation:bump .35s var(--ease)}
.empty .icon{animation:float 3.2s ease-in-out infinite}

/* logs */
.log.is-new{animation:logIn .5s var(--ease)}
.log.removing{overflow:hidden;opacity:0;transform:translateX(24px);height:0!important;margin-bottom:0;border-width:0;transition:height .3s var(--ease),opacity .2s ease,transform .3s var(--ease),margin .3s var(--ease)}
.log.sweep{opacity:0;transform:translateX(28px);transition:opacity .25s ease,transform .3s var(--ease)}

/* toasts */
.toast{position:relative;overflow:hidden;animation:toastIn .35s var(--ease)}
.toast::after{content:'';position:absolute;left:0;bottom:0;height:3px;width:100%;background:var(--info);transform-origin:left;animation:bar 3.4s linear forwards}
.toast.success::after{background:var(--ok)}
.toast.error::after{background:var(--danger)}

/* modal */
.modal{animation:fadeIn .18s ease both}
.modal .dialog{animation:dialogIn .3s var(--ease) both}
.modal.closing{animation:fadeOut .17s ease both}
.modal.closing .dialog{animation:dialogOut .17s ease both}

@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
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
      <div><strong>NexRelay</strong><span>Integration Hub</span></div>
    </div>
    <div class="nav-label">Workspace</div>
    <nav class="nav" aria-label="Primary">
      <span class="nav-indicator" id="navIndicator" aria-hidden="true"></span>
      <button type="button" class="nav-item active" data-panel="inbound"><svg class="icon"><use href="#i-in"/></svg>Inbound webhook</button>
      <button type="button" class="nav-item" data-panel="outbound"><svg class="icon"><use href="#i-out"/></svg>Outbound client</button>
      <button type="button" class="nav-item" data-panel="logs"><svg class="icon"><use href="#i-list"/></svg>Execution logs<span class="count" id="logCount">0</span></button>
    </nav>
    <div class="side-foot">
      <div class="lbl">Workspace ID</div>
      <code id="deviceIdBadge">—</code>
      <button type="button" class="btn-side" id="newSessionBtn">New workspace</button>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div><h1 id="pageTitle"></h1><p id="pageSub"></p></div>
      <div class="status" id="statusPill"><span class="dot"></span><span id="statusText">Checking gateway…</span></div>
    </header>

    <!-- Inbound -->
    <section id="panel-inbound" class="panel active">
      <div class="card">
        <div class="card-head"><div><h2>Webhook endpoint</h2><p>Send an HTTPS POST with a JSON body. Every request must authenticate with a credential below.</p></div></div>
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
          <div><h2>Credentials</h2><p>A new token, password, API key and client secret are issued on every page load. Older ones stop working immediately.</p></div>
          <button type="button" class="btn btn-secondary btn-sm" id="rotateBtn"><svg class="icon"><use href="#i-refresh"/></svg>Rotate now</button>
        </div>
        <div class="card-body">
          <div class="seg" role="tablist" aria-label="Authentication method">
            <button type="button" class="active" data-tab-group="cred" data-tab-target="cred-bearer">Bearer token</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-basic">Basic auth</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-key">API key</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-oauth">OAuth 2.0</button>
          </div>

          <!-- Bearer: Authorization + Bearer are separate, read-only, colour-coded; the token is its own field -->
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
              <button type="button" class="btn btn-secondary btn-sm" data-copy-header><svg class="icon"><use href="#i-copy"/></svg>Copy header value</button>
            </div>
            <p class="hint">In ServiceNow, add an HTTP header named <b>Authorization</b> to the REST message with the value <b>Bearer</b>, a space, then the token.</p>
          </div>

          <div class="tab-panel" data-panel-group="cred" id="cred-basic" hidden>
            <div class="grid-2">
              <div class="field">
                <label for="basicUserBox">Username (permanent)</label>
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
            <p class="hint">In ServiceNow, set the REST message Authentication type to <b>Basic</b> and use a Basic auth profile with these credentials.</p>
          </div>

          <div class="tab-panel" data-panel-group="cred" id="cred-key" hidden>
            <div class="field">
              <label for="apiKeyBox">API key</label>
              <div class="input-group">
                <input type="password" id="apiKeyBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                <button type="button" class="icon-btn" data-reveal="apiKeyBox" title="Show / hide" aria-label="Show or hide API key"><svg class="icon"><use href="#i-eye"/></svg></button>
                <button type="button" class="icon-btn" data-copy="apiKeyBox" data-label="API key" title="Copy" aria-label="Copy API key"><svg class="icon"><use href="#i-copy"/></svg></button>
              </div>
            </div>

            <div class="opt-title">Send it as one of</div>
            <div class="auth-row opt">
              <div class="field">
                <label for="keyViaHeader">Delivery</label>
                <input type="text" id="keyViaHeader" class="tag tag-amber" value="HTTP header" readonly aria-readonly="true">
              </div>
              <div class="field">
                <label for="keyHeaderName">Header name</label>
                <input type="text" id="keyHeaderName" class="tag tag-green" value="x-sn-apikey" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="note-cell">The header value is the API key. <code>x-api-key</code> is accepted as well.</div>
            </div>
            <div class="auth-row opt">
              <div class="field">
                <label for="keyViaQuery">Delivery</label>
                <input type="text" id="keyViaQuery" class="tag tag-amber" value="Query string" readonly aria-readonly="true">
              </div>
              <div class="field">
                <label for="keyQueryName">Parameter</label>
                <input type="text" id="keyQueryName" class="tag tag-rose" value="api_key" readonly aria-readonly="true" spellcheck="false">
              </div>
              <div class="field">
                <label for="apiQueryBox">Full URL with key</label>
                <div class="input-group">
                  <input type="password" id="apiQueryBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-reveal="apiQueryBox" title="Show / hide" aria-label="Show or hide URL"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="apiQueryBox" data-label="URL with API key" title="Copy" aria-label="Copy URL with key"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint">In ServiceNow, add the key as an HTTP header on the REST message, or as a query parameter on the endpoint URL. Prefer the header: query strings can end up in proxy and server logs.</p>
          </div>

          <div class="tab-panel" data-panel-group="cred" id="cred-oauth" hidden>
            <div class="auth-row two">
              <div class="field">
                <label for="oauthGrant">Grant type</label>
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
                <label for="oauthIdBox">Client ID (stable for this workspace)</label>
                <div class="input-group">
                  <input type="text" id="oauthIdBox" readonly spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-copy="oauthIdBox" data-label="Client ID" title="Copy" aria-label="Copy client ID"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="field">
                <label for="oauthSecretBox">Client secret</label>
                <div class="input-group">
                  <input type="password" id="oauthSecretBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Issuing…">
                  <button type="button" class="icon-btn" data-reveal="oauthSecretBox" title="Show / hide" aria-label="Show or hide client secret"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="oauthSecretBox" data-label="Client secret" title="Copy" aria-label="Copy client secret"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint">In ServiceNow, set the REST message Authentication type to <b>OAuth 2.0</b> and point its OAuth profile at this token URL with the client ID and secret. The hub accepts the credentials in the form body or as HTTP Basic. Access tokens last one hour and are revoked when you refresh this page.</p>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>Quick test</h2><p>A ready-to-run cURL command for the method selected above.</p></div>
          <button type="button" class="btn btn-secondary btn-sm" data-copy="curlBox" data-label="cURL command"><svg class="icon"><use href="#i-copy"/></svg>Copy</button>
        </div>
        <div class="card-body"><pre id="curlBox">Issuing credentials…</pre></div>
      </div>
    </section>

    <!-- Outbound -->
    <section id="panel-outbound" class="panel">
      <div class="card">
        <div class="card-head"><div><h2>Request builder</h2><p>Run authenticated calls against your ServiceNow Table API or Scripted REST APIs.</p></div></div>
        <div class="card-body">
          <div class="url-bar">
            <select id="httpMethod" aria-label="HTTP method">
              <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
            </select>
            <input type="url" id="httpUrl" placeholder="https://dev12345.service-now.com/api/now/table/incident" spellcheck="false" aria-label="Request URL">
            <button type="button" class="btn btn-primary" id="sendBtn"><svg class="icon"><use href="#i-send"/></svg>Send request</button>
          </div>

          <div class="seg" role="tablist" aria-label="Request sections">
            <button type="button" class="active" data-tab-group="pm" data-tab-target="pm-auth">Authorization</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-headers">Headers</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-body">Body</button>
          </div>

          <div class="tab-panel" data-panel-group="pm" id="pm-auth">
            <div class="field">
              <label for="authType">Auth type</label>
              <select id="authType">
                <option value="basic">Basic auth</option>
                <option value="bearer">Bearer token (OAuth 2.0)</option>
                <option value="apikey">API key (custom header)</option>
                <option value="none">No auth</option>
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
              <label for="bearerToken">Access token</label>
              <div class="input-group">
                <input type="password" id="bearerToken" placeholder="Paste OAuth bearer token" autocomplete="new-password">
                <button type="button" class="icon-btn" data-reveal="bearerToken" title="Show / hide" aria-label="Show or hide token"><svg class="icon"><use href="#i-eye"/></svg></button>
              </div>
            </div>
            <div id="apiKeyAuthFields" class="grid-2" hidden>
              <div class="field"><label for="apiKeyHeaderName">Header name</label><input type="text" id="apiKeyHeaderName" value="x-sn-apikey" autocomplete="off"></div>
              <div class="field">
                <label for="apiKeyValue">API key</label>
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
            <button type="button" class="btn btn-secondary btn-sm" id="addHeaderBtn">+ Add header</button>
          </div>

          <div class="tab-panel" data-panel-group="pm" id="pm-body" hidden>
            <label for="httpBody">Raw JSON body</label>
            <textarea id="httpBody" rows="8" spellcheck="false">{
  "short_description": "Incident created via NexRelay Hub",
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
          <button type="button" class="active" data-filter="all">All</button>
          <button type="button" data-filter="inbound">Inbound</button>
          <button type="button" data-filter="outbound">Outbound</button>
        </div>
        <div class="spacer"></div>
        <button type="button" class="btn btn-danger-ghost btn-sm" id="clearAllBtn"><svg class="icon"><use href="#i-trash"/></svg>Delete all records</button>
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
    inbound: ['Inbound webhook', 'Receive ServiceNow payloads on a secured, workspace-scoped endpoint.'],
    outbound: ['Outbound HTTP client', 'Send authenticated requests to your ServiceNow instance.'],
    logs: ['Execution logs', 'Audit trail of inbound and outbound traffic for this workspace.']
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

  /* ---------- toasts & dialogs ---------- */
  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || 'info');
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(function () {
      el.classList.add('out');
      setTimeout(function () { el.remove(); }, 260);
    }, 3400);
  }

  var modalResolve = null;
  var modalTimer = null;
  function confirmDialog(opts) {
    return new Promise(function (resolve) {
      $('modalTitle').textContent = opts.title;
      $('modalBody').textContent = opts.message;
      var ok = $('modalConfirm');
      ok.textContent = opts.confirmLabel || 'Confirm';
      ok.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');
      clearTimeout(modalTimer);
      $('modal').classList.remove('closing');
      $('modal').hidden = false;
      $('modalCancel').focus();
      modalResolve = resolve;
    });
  }
  function closeModal(result) {
    var m = $('modal');
    m.classList.add('closing');
    clearTimeout(modalTimer);
    modalTimer = setTimeout(function () { m.hidden = true; m.classList.remove('closing'); }, 170);
    if (modalResolve) { var r = modalResolve; modalResolve = null; r(result); }
  }

  /* ---------- clipboard ---------- */
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
    function fail() { toast('Copy failed - select the text and copy manually', 'error'); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value) ? done() : fail(); });
    } else {
      fallbackCopy(value) ? done() : fail();
    }
  }

  /* ---------- motion helpers ---------- */
  function swapIcon(btn, id, noPop) {
    var u = btn.querySelector('use');
    if (!u) return;
    u.setAttribute('href', '#' + id);
    if (!noPop) { btn.classList.remove('pop'); void btn.offsetWidth; btn.classList.add('pop'); }
  }

  function flashCopied(btn) {
    if (!btn) return;
    var u = btn.querySelector('use');
    if (!u) return;
    if (!btn.getAttribute('data-orig')) btn.setAttribute('data-orig', u.getAttribute('href').slice(1));
    swapIcon(btn, 'i-check');
    btn.classList.add('copied');
    clearTimeout(btn._t);
    btn._t = setTimeout(function () {
      swapIcon(btn, btn.getAttribute('data-orig'), true);
      btn.classList.remove('copied');
    }, 1400);
  }

  function moveIndicator() {
    var ind = $('navIndicator');
    var active = document.querySelector('.nav-item.active');
    if (!ind || !active || !active.offsetWidth) return;
    var first = !ind.getAttribute('data-ready');
    if (first) ind.style.transition = 'none';
    ind.style.width = active.offsetWidth + 'px';
    ind.style.height = active.offsetHeight + 'px';
    ind.style.transform = 'translate(' + active.offsetLeft + 'px,' + active.offsetTop + 'px)';
    if (first) { void ind.offsetWidth; ind.style.transition = ''; ind.setAttribute('data-ready', '1'); }
  }

  function placeThumb(seg) {
    var thumb = seg.querySelector('.seg-thumb');
    var active = seg.querySelector('button.active');
    if (!thumb || !active || !active.offsetWidth) return;
    var first = !thumb.getAttribute('data-ready');
    if (first) thumb.style.transition = 'none';
    thumb.style.width = active.offsetWidth + 'px';
    thumb.style.height = active.offsetHeight + 'px';
    thumb.style.transform = 'translate(' + active.offsetLeft + 'px,' + active.offsetTop + 'px)';
    if (first) { void thumb.offsetWidth; thumb.style.transition = ''; thumb.setAttribute('data-ready', '1'); }
  }

  function updateThumbs() {
    Array.prototype.forEach.call(document.querySelectorAll('.seg'), placeThumb);
  }

  function initMotion() {
    Array.prototype.forEach.call(document.querySelectorAll('.seg'), function (seg) {
      var t = document.createElement('span');
      t.className = 'seg-thumb';
      t.setAttribute('aria-hidden', 'true');
      seg.insertBefore(t, seg.firstChild);
    });
    function relayout() { moveIndicator(); updateThumbs(); }
    window.addEventListener('resize', relayout);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(relayout);
  }

  var CRED_IDS = ['bearerBox', 'basicUserBox', 'basicPassBox', 'apiKeyBox', 'apiQueryBox', 'oauthIdBox', 'oauthSecretBox'];
  function eachCredGroup(fn) {
    CRED_IDS.forEach(function (id) { var el = $(id); if (el && el.parentElement) fn(el.parentElement); });
  }
  function setCredLoading(on) {
    eachCredGroup(function (g) { g.classList.toggle('shimmer', !!on); });
  }
  function flashCreds() {
    eachCredGroup(function (g) { g.classList.remove('flash'); void g.offsetWidth; g.classList.add('flash'); });
    setTimeout(function () { eachCredGroup(function (g) { g.classList.remove('flash'); }); }, 1100);
  }

  function collapseCard(id) {
    return new Promise(function (resolve) {
      var el = document.querySelector('[data-card="' + String(id).replace(/"/g, '') + '"]');
      if (!el) { resolve(); return; }
      el.style.height = el.offsetHeight + 'px';
      void el.offsetWidth;
      el.classList.add('removing');
      setTimeout(resolve, 300);
    });
  }

  function sweepCards() {
    return new Promise(function (resolve) {
      var cards = document.querySelectorAll('#logsList .log');
      var n = Math.min(cards.length, 8);
      Array.prototype.forEach.call(cards, function (c, i) {
        c.style.transitionDelay = Math.min(i, 8) * 35 + 'ms';
        c.classList.add('sweep');
      });
      setTimeout(resolve, cards.length ? n * 35 + 320 : 0);
    });
  }

  /* ---------- navigation ---------- */
  function showPanel(name) {
    Array.prototype.forEach.call(document.querySelectorAll('.panel'), function (p) {
      p.classList.toggle('active', p.id === 'panel-' + name);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (b) {
      b.classList.toggle('active', b.getAttribute('data-panel') === name);
    });
    $('pageTitle').textContent = PAGES[name][0];
    $('pageSub').textContent = PAGES[name][1];
    requestAnimationFrame(function () { moveIndicator(); updateThumbs(); });
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
    updateThumbs();
  }

  /* ---------- workspace & credentials ---------- */
  function getDeviceId() {
    var id = '';
    try { id = localStorage.getItem('nex_device_token') || ''; } catch (e) { id = ''; }
    if (!DEVICE_RE.test(id)) {
      id = 'sn_dev_' + hex(24);
      try { localStorage.setItem('nex_device_token', id); } catch (e) {}
    }
    // Credentials are no longer stored in the browser.
    try {
      ['nex_device_user', 'nex_device_pass', 'nex_device_apikey'].forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
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
    $('apiQueryBox').value = url + '?api_key=' + c.apiKey;
    $('oauthIdBox').value = c.clientId;
    $('oauthSecretBox').value = c.clientSecret;
    if (c.allowedHosts && c.allowedHosts.length) {
      $('hostHint').textContent = 'Requests are restricted to HTTPS hosts matching: ' + c.allowedHosts.join(', ') + '.';
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
        "# 2) Call the webhook with the returned access_token\n" +
        head + "  -H 'Authorization: Bearer <access_token>' \\\n" + tail;
    } else {
      out = head + "  -H 'Authorization: Bearer " + c.bearer + "' \\\n" + tail;
    }
    box.textContent = out;
  }

  function rotateCredentials(manual) {
    setCredLoading(!state.creds);
    $('rotateBtn').classList.add('busy');
    return fetch(API + '/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: state.deviceId })
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (c) {
      state.creds = c;
      setCredLoading(false);
      flashCreds();
      renderCredentials();
      if (manual) toast('New credentials issued. Previous ones are revoked.', 'success');
    }).catch(function (e) {
      toast('Could not issue credentials: ' + e.message, 'error');
    });
  }

  /* ---------- logs ---------- */
  function signature(inb, out) {
    return (inb[0] ? inb[0].id : '') + '|' + (out[0] ? out[0].id : '') + '|' + inb.length + '|' + out.length;
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
          state.primed = true; // logs that already exist on first load appear without the "new" animation
          d.inbound.concat(d.outbound).forEach(function (i) { state.seen[i.id] = true; });
        }
        renderLogs();
      }).catch(function () {});
  }

  function badge(text, cls) { return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }

  function block(label, data) {
    if (data === null || data === undefined || data === '') return '';
    var text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    var cut = false;
    if (text.length > MAX_RENDER_CHARS) { text = text.slice(0, MAX_RENDER_CHARS); cut = true; }
    return '<div class="block"><div class="block-label">' + esc(label) + '</div><pre>' + esc(text) + '</pre>' +
      (cut ? '<div class="trunc">Output truncated at ' + MAX_RENDER_CHARS.toLocaleString() + ' characters.</div>' : '') + '</div>';
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
    return '<article class="log' + (state.seen[item.id] ? '' : ' is-new') + '" data-card="' + esc(item.id) + '">' +
      '<div class="log-head"><div class="log-title">' + head + '</div>' +
      '<div class="log-actions"><span class="log-meta">' + formatTime(item.timestamp) + '</span>' + delBtn + '</div></div>' +
      (inbound ? '' : '<div class="log-url">' + esc(item.url) + '</div>') +
      (body ? '<details data-id="' + esc(item.id) + '"' + open + '><summary>' + (inbound ? 'Payload' : 'Request &amp; response') + '</summary>' + body + '</details>' : '') +
      '</article>';
  }

  function renderLogs() {
    var all = state.outbound.concat(state.inbound).sort(function (a, b) {
      return new Date(b.timestamp) - new Date(a.timestamp);
    });
    var cnt = $('logCount');
    if (cnt.textContent !== String(all.length)) {
      cnt.textContent = all.length;
      cnt.classList.remove('bump'); void cnt.offsetWidth; cnt.classList.add('bump');
    }
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
      title: 'Delete this record?',
      message: 'Record ' + id + ' will be permanently removed from this workspace.',
      confirmLabel: 'Delete record', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs/' + encodeURIComponent(id), { method: 'DELETE', headers: { 'X-Device-Token': state.deviceId } })
        .then(function (r) {
          if (r.ok) {
            return collapseCard(id).then(function () {
              state.inbound = state.inbound.filter(function (i) { return i.id !== id; });
              state.outbound = state.outbound.filter(function (i) { return i.id !== id; });
              delete state.open[id];
              resetSignature(); renderLogs();
              toast('Record ' + id + ' deleted', 'success');
            });
          } else if (r.status === 404) {
            state.sig = ''; loadLogs();
            toast('That record was already removed', 'info');
          } else {
            toast('Could not delete the record', 'error');
          }
        });
    }).catch(function () { toast('Could not delete the record', 'error'); });
  }

  function deleteAll() {
    var total = state.inbound.length + state.outbound.length;
    if (!total) { toast('There are no records to delete', 'info'); return; }
    confirmDialog({
      title: 'Delete all records?',
      message: 'All ' + total + ' inbound and outbound records in this workspace will be permanently deleted. This cannot be undone.',
      confirmLabel: 'Delete ' + total + ' records', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs', { method: 'DELETE', headers: { 'X-Device-Token': state.deviceId } })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)); })
        .then(function (d) {
          return sweepCards().then(function () {
            state.inbound = []; state.outbound = []; state.open = {};
            resetSignature(); renderLogs();
            toast(d.deleted + ' record' + (d.deleted === 1 ? '' : 's') + ' deleted', 'success');
          });
        });
    }).catch(function () { toast('Could not delete the records', 'error'); });
  }

  /* ---------- outbound ---------- */
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
      catch (e) { toast('The request body is not valid JSON', 'error'); return; }
    }

    state.sending = true;
    var btn = $('sendBtn');
    btn.disabled = true;
    btn.classList.add('loading');
    btn.lastChild.textContent = 'Sending…';

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
        resetSignature(); renderLogs();
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
      btn.classList.remove('loading');
      btn.lastChild.textContent = 'Send request';
    });
  }

  /* ---------- health ---------- */
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

  /* ---------- events ---------- */
  document.addEventListener('click', function (e) {
    var t = e.target;
    var el;

    if ((el = t.closest('[data-copy-header]'))) {
      if (!state.creds) { toast('Credentials are still being issued', 'error'); return; }
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
      updateThumbs();
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

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !$('modal').hidden) closeModal(false);
  });

  $('modalConfirm').addEventListener('click', function () { closeModal(true); });
  $('modalCancel').addEventListener('click', function () { closeModal(false); });
  $('modal').addEventListener('click', function (e) { if (e.target === $('modal')) closeModal(false); });

  $('rotateBtn').addEventListener('click', function () { rotateCredentials(true); });
  $('clearAllBtn').addEventListener('click', deleteAll);
  $('sendBtn').addEventListener('click', sendOutbound);
  $('addHeaderBtn').addEventListener('click', function () { addHeaderRow('', ''); });
  $('authType').addEventListener('change', updateAuthFields);
  $('httpMethod').addEventListener('change', updateBodyState);
  $('httpUrl').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendOutbound(); });

  $('newSessionBtn').addEventListener('click', function () {
    confirmDialog({
      title: 'Start a new workspace?',
      message: 'You will get a new endpoint URL and an empty log history. The current URL will stop receiving traffic in this browser.',
      confirmLabel: 'Create workspace'
    }).then(function (yes) {
      if (!yes) return;
      state.deviceId = 'sn_dev_' + hex(24);
      try { localStorage.setItem('nex_device_token', state.deviceId); } catch (e) {}
      state.creds = null; state.inbound = []; state.outbound = []; state.open = {}; state.sig = '';
      renderCredentials(); renderLogs();
      rotateCredentials(false).then(function () { toast('New workspace created', 'success'); });
    });
  });

  /* ---------- init ---------- */
  state.deviceId = getDeviceId();
  addHeaderRow('Accept', 'application/json');
  updateAuthFields();
  updateBodyState();
  initMotion();
  showPanel('inbound');
  renderCredentials();
  renderLogs();
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
    console.log(`NexRelay ServiceNow Integration Hub running on port ${PORT}`);
});