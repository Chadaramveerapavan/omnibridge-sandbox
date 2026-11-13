const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;

// ---- Configuration ----
const MAX_LOGS = 200;
const BASIC_USERNAME = process.env.BASIC_USERNAME || 'nexrelay_admin';
const INBOUND_TOKEN = process.env.INBOUND_TOKEN || '';
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '.service-now.com')
    .split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
const OUTBOUND_TIMEOUT_MS = 30000;
const OAUTH_TOKEN_TTL_S = Number(process.env.OAUTH_TOKEN_TTL_S) || 3600;
const OAUTH_MAX_TOKENS = 20;

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

// ---- Global State Store ----
const globalStore = { inbound: [], outbound: [] };
let activeSession = null;

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

// ---- Cryptographic Credentials Engine ----
const digest = v => crypto.createHash('sha256').update(String(v)).digest();
const matches = (candidate, storedDigest) => crypto.timingSafeEqual(digest(candidate), storedDigest);
const randomSecret = (prefix, bytes) => prefix + crypto.randomBytes(bytes).toString('hex');
const newSyncId = prefix => prefix + crypto.randomInt(100000, 1000000);
const sameText = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

function issueGlobalCredentials() {
    const creds = {
        username: BASIC_USERNAME,
        clientId: 'nexrelay_' + crypto.randomBytes(6).toString('hex'),
        password: randomSecret('sn_pass_', 16),
        apiKey: randomSecret('sn_key_', 20),
        bearer: randomSecret('sn_nex_', 24),
        clientSecret: randomSecret('sn_sec_', 24)
    };
    activeSession = {
        raw: creds,
        bearer: digest(creds.bearer),
        apiKey: digest(creds.apiKey),
        password: digest(creds.password),
        clientId: digest(creds.clientId),
        clientSecret: digest(creds.clientSecret),
        tokens: []
    };
    return creds;
}

issueGlobalCredentials();

function hasValidOAuthToken(session, candidate) {
    const now = Date.now();
    session.tokens = session.tokens.filter(t => t.exp > now);
    let ok = false;
    for (const t of session.tokens) {
        if (matches(candidate, t.digest)) ok = true;
    }
    return ok;
}

function authenticateInbound(req) {
    const auth = req.headers['authorization'] || '';
    const headerKey = req.headers['x-sn-apikey'] || req.headers['x-api-key'] || '';

    if (INBOUND_TOKEN && auth === 'Bearer ' + INBOUND_TOKEN) return 'Static Bearer Token';
    if (!activeSession) return null;

    if (auth.startsWith('Bearer ')) {
        const candidate = auth.slice(7).trim();
        if (candidate && matches(candidate, activeSession.bearer)) return 'Bearer Token';
        if (candidate && hasValidOAuthToken(activeSession, candidate)) return 'OAuth 2.0 (Client Credentials)';
    }
    if (auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx > -1) {
            const user = decoded.slice(0, idx);
            const pass = decoded.slice(idx + 1);
            if (sameText(user, BASIC_USERNAME) && matches(pass, activeSession.password)) return 'Basic Auth';
        }
    }
    if (headerKey && matches(headerKey, activeSession.apiKey)) return 'API Key (Header)';
    return null;
}

// ---- API Routes ----
app.get('/api/servicenow/credentials', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ ...activeSession.raw, tokenTtlSeconds: OAUTH_TOKEN_TTL_S, allowedHosts: ALLOWED_HOSTS });
});

app.post('/api/servicenow/credentials/rotate', (req, res) => {
    const creds = issueGlobalCredentials();
    res.set('Cache-Control', 'no-store');
    res.json({ ...creds, tokenTtlSeconds: OAUTH_TOKEN_TTL_S, allowedHosts: ALLOWED_HOSTS });
});

app.post('/api/servicenow/oauth/token', (req, res) => {
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
    const body = req.body || {};

    if (body.grant_type !== 'client_credentials') {
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only client_credentials grant is supported.' });
    }

    let clientId = typeof body.client_id === 'string' ? body.client_id : '';
    let clientSecret = typeof body.client_secret === 'string' ? body.client_secret : '';
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx > -1) { clientId = decoded.slice(0, idx); clientSecret = decoded.slice(idx + 1); }
    }

    const valid = activeSession && clientId && clientSecret &&
        matches(clientId, activeSession.clientId) && matches(clientSecret, activeSession.clientSecret);
    if (!valid) {
        res.set('WWW-Authenticate', 'Basic realm="NexRelay OAuth"');
        return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client or wrong secret.' });
    }

    const accessToken = randomSecret('sn_oat_', 24);
    activeSession.tokens = activeSession.tokens
        .filter(t => t.exp > Date.now())
        .concat({ digest: digest(accessToken), exp: Date.now() + OAUTH_TOKEN_TTL_S * 1000 })
        .slice(-OAUTH_MAX_TOKENS);

    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: OAUTH_TOKEN_TTL_S });
});

// Clean Inbound Webhook Endpoint
app.post('/api/servicenow/inbound', (req, res) => {
    const authMethod = authenticateInbound(req);
    if (!authMethod) {
        res.set('WWW-Authenticate', 'Bearer realm="NexRelay"');
        return res.status(401).json({
            status: 'Error',
            message: 'Authentication failed: Provide a valid Bearer token, Basic credentials, API key, or OAuth access token.'
        });
    }

    const syncId = newSyncId('SN-INB-');
    const inboundEntry = {
        id: syncId,
        direction: 'INBOUND',
        authMethod,
        timestamp: new Date().toISOString(),
        headers: { 'content-type': req.headers['content-type'] },
        payload: req.body
    };

    addLog(globalStore.inbound, inboundEntry);
    res.status(200).json({ status: 'Success', message: 'Inbound ServiceNow payload successfully ingested.', record: inboundEntry });
});

// Outbound Proxy
app.post('/api/servicenow/outbound', async (req, res) => {
    const { method, url, authType, basicUser, basicPass, bearerToken, apiKeyHeaderName, apiKeyValue, headers, body } = req.body || {};

    if (!url || !method) {
        return res.status(400).json({ status: 'Error', message: 'Validation Error: Method and URL are required.' });
    }
    if (!isAllowedUrl(url)) {
        return res.status(400).json({ status: 'Error', message: 'Blocked: only https URLs on allowed hosts are permitted.' });
    }

    const syncId = newSyncId('SN-OUT-');
    const timestamp = new Date().toISOString();
    const startTime = Date.now();

    const requestHeaders = { 'Accept': 'application/json', 'Content-Type': 'application/json' };
    if (headers && typeof headers === 'object') {
        Object.entries(headers).forEach(([k, v]) => { if (k && k.trim()) requestHeaders[k.trim()] = v; });
    }

    if (authType === 'basic' && basicUser) {
        requestHeaders['Authorization'] = 'Basic ' + Buffer.from(`${basicUser}:${basicPass || ''}`).toString('base64');
    } else if (authType === 'bearer' && bearerToken) {
        requestHeaders['Authorization'] = `Bearer ${bearerToken}`;
    } else if (authType === 'apikey' && apiKeyValue) {
        requestHeaders[(apiKeyHeaderName && apiKeyHeaderName.trim()) ? apiKeyHeaderName.trim() : 'x-sn-apikey'] = apiKeyValue;
    }

    const fetchOptions = { method: String(method).toUpperCase(), headers: requestHeaders };
    if (['POST', 'PUT', 'PATCH'].includes(fetchOptions.method) && body) {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    let responseStatus = 200;
    let statusText = 'OK';
    let responseData = null;
    let durationMs = 0;
    let diagnosticError = null;

    try {
        const response = await fetch(url, { ...fetchOptions, redirect: 'manual', signal: AbortSignal.timeout(OUTBOUND_TIMEOUT_MS) });
        durationMs = Date.now() - startTime;
        responseStatus = response.status;
        statusText = response.statusText;
        const rawText = await response.text();
        try { responseData = JSON.parse(rawText); } catch { responseData = rawText || { message: 'Empty response body.' }; }
    } catch (error) {
        durationMs = Date.now() - startTime;
        responseStatus = 503;
        statusText = error.name === 'TimeoutError' ? 'Request Timed Out' : 'Network Failure';
        diagnosticError = error.message;
        responseData = { error: error.message, diagnosticAdvice: 'Verify ServiceNow instance connectivity.' };
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

    addLog(globalStore.outbound, outboundEntry);
    res.status(200).json({ status: 'Completed', record: outboundEntry });
});

app.get('/api/servicenow/logs', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ inbound: globalStore.inbound, outbound: globalStore.outbound });
});

app.delete('/api/servicenow/logs', (req, res) => {
    const deleted = globalStore.inbound.length + globalStore.outbound.length;
    globalStore.inbound = [];
    globalStore.outbound = [];
    res.json({ status: 'Cleared', deleted });
});

app.delete('/api/servicenow/logs/:id', (req, res) => {
    const targetId = req.params.id;
    const before = globalStore.inbound.length + globalStore.outbound.length;
    globalStore.inbound = globalStore.inbound.filter(item => item.id !== targetId);
    globalStore.outbound = globalStore.outbound.filter(item => item.id !== targetId);
    if (globalStore.inbound.length + globalStore.outbound.length === before) {
        return res.status(404).json({ status: 'Error', message: 'Record not found.' });
    }
    res.json({ status: 'Success', message: `Record ${targetId} deleted.`, deleted: 1 });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
});

// ---- Stunning Animated Frontend UI (Matrix Edition) ----
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexRelay · Matrix Command Center</title>
<style>
:root{
  --bg:#010409;--surface:#0d1117;--surface-2:#161b22;--border:#30363d;--border-strong:#484f58;
  --text:#f0f6fc;--muted:#8b949e;--accent:#2ea043;--accent-hover:#238636;--accent-ink:#ffffff;--accent-soft:rgba(46,160,67,0.15);
  --danger:#f85149;--danger-soft:rgba(248,81,73,0.15);--ok:#3fb950;--ok-soft:rgba(63,185,80,0.15);
  --warn:#d29922;--warn-soft:rgba(210,153,34,0.15);--info:#58a6ff;--info-soft:rgba(88,166,255,0.15);
  --side:#010409;--side-active:#1f6feb26;
  --shadow:0 16px 32px rgba(1,4,9,0.8), 0 0 20px rgba(46,160,67,0.1);
  --shadow-lg:0 24px 64px rgba(1,4,9,0.95), 0 0 40px rgba(46,160,67,0.2);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}

/* Animated Cyber Matrix Background Glow */
body::before{
  content:'';position:fixed;inset:0;z-index:-1;
  background: radial-gradient(circle at 15% 15%, rgba(46,160,67,0.08) 0%, transparent 40%),
              radial-gradient(circle at 85% 85%, rgba(88,166,255,0.08) 0%, transparent 40%),
              linear-gradient(to right, rgba(48,54,61,0.15) 1px, transparent 1px),
              linear-gradient(to bottom, rgba(48,54,61,0.15) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 50px 50px, 50px 50px;
  animation: bgPulse 8s ease-in-out infinite alternate;
}
@keyframes bgPulse{0%{opacity:0.8}100%{opacity:1}}

[hidden]{display:none!important}
button{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

.app{display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh;animation: appEntrance 0.7s cubic-bezier(0.16, 1, 0.3, 1) forwards}
@keyframes appEntrance{from{opacity:0;transform:translateY(15px) scale(0.99)}to{opacity:1;transform:none}}

.sidebar{background:var(--side);color:var(--muted);display:flex;flex-direction:column;padding:30px 20px;position:sticky;top:0;height:100vh;border-right:1px solid var(--border);backdrop-filter:blur(16px)}
.brand{display:flex;align-items:center;gap:14px;padding:4px 8px 36px}
.brand-mark{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#2ea043,#1f6feb);display:grid;place-items:center;color:#fff;box-shadow:0 0 25px rgba(46,160,67,0.4);animation: iconFloat 4s ease-in-out infinite}
@keyframes iconFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
.brand-mark .icon{width:24px;height:24px}
.brand strong{display:block;color:#fff;font-size:18px;letter-spacing:0.3px}
.brand span{font-size:11.5px;color:var(--ok);font-weight:700;text-transform:uppercase;letter-spacing:1px}

.nav{display:flex;flex-direction:column;gap:8px}
.nav-label{font-size:11px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;padding:0 12px 10px;color:var(--muted)}
.nav-item{display:flex;align-items:center;gap:12px;width:100%;padding:13px 16px;border:0;border-radius:12px;background:transparent;color:var(--muted);font-weight:600;text-align:left;cursor:pointer;transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1);position:relative;overflow:hidden}
.nav-item:hover{background:rgba(255,255,255,0.04);color:#fff;transform:translateX(4px)}
.nav-item.active{background:var(--surface-2);color:#fff;box-shadow:inset 3px 0 0 var(--accent);border:1px solid var(--border)}
.count{margin-left:auto;min-width:26px;padding:3px 8px;border-radius:999px;background:var(--ok-soft);color:var(--ok);font-size:11px;font-weight:700;text-align:center}

.side-foot{margin-top:auto;padding:20px 14px 0;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
.side-foot .lbl{text-transform:uppercase;letter-spacing:1px;font-size:10.5px;color:var(--ok);font-weight:800;margin-bottom:6px}

.main{padding:36px 48px 72px;width:100%;max-width:1340px;animation: mainSlide 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards}
@keyframes mainSlide{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}

.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:32px}
.topbar h1{margin:0;font-size:28px;font-weight:800;letter-spacing:-0.5px;color:var(--text)}
.topbar p{margin:6px 0 0;color:var(--muted);font-size:14px}
.status{display:inline-flex;align-items:center;gap:10px;padding:9px 18px;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:12.5px;font-weight:700;white-space:nowrap;box-shadow:var(--shadow)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);transition:all 0.3s}
.status.ok .dot{background:var(--ok);box-shadow:0 0 0 6px var(--ok-soft), 0 0 15px var(--ok)}
.status.bad .dot{background:var(--danger);box-shadow:0 0 0 6px var(--danger-soft), 0 0 15px var(--danger)}

/* Telemetry Metrics Grid */
.metrics-bar{display:grid;grid-template-columns:repeat(4, 1fr);gap:18px;margin-bottom:32px}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px 24px;box-shadow:var(--shadow);transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);position:relative;overflow:hidden}
.metric-card::after{content:'';position:absolute;top:0;left:0;width:100%;height:3px;background:linear-gradient(90deg, transparent, var(--accent), transparent);opacity:0;transition:opacity 0.3s}
.metric-card:hover{transform:translateY(-4px);border-color:var(--accent);box-shadow:var(--shadow-lg)}
.metric-card:hover::after{opacity:1}
.metric-card .label{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:8px}
.metric-card .value{font-size:24px;font-weight:800;font-family:var(--mono);color:var(--text)}

.panel{display:none}
.panel.active{display:block;animation: panelReveal 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards}
@keyframes panelReveal{from{opacity:0;transform:scale(0.99) translateY(10px)}to{opacity:1;transform:none}}

.card{background:var(--surface);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);margin-bottom:28px;overflow:hidden;transition:border-color 0.3s}
.card:hover{border-color:var(--border-strong)}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:24px 28px;border-bottom:1px solid var(--border);background:var(--surface-2)}
.card-head h2{margin:0;font-size:18px;font-weight:750}
.card-head p{margin:6px 0 0;color:var(--muted);font-size:13.5px}
.card-body{padding:28px}

label{display:block;margin-bottom:9px;font-size:11.5px;font-weight:800;color:var(--muted);letter-spacing:0.8px;text-transform:uppercase}
.field{margin-bottom:22px}
.field:last-child{margin-bottom:0}
input,select,textarea{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:12px;padding:12px 18px;font:inherit;transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1)}
textarea{font-family:var(--mono);font-size:13.5px;resize:vertical;min-height:180px}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft);outline:none;background:var(--surface-2)}
.input-group{display:flex;align-items:stretch;border:1px solid var(--border);border-radius:12px;background:var(--bg);overflow:hidden;transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1)}
.input-group:focus-within{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
.input-group input{border:0;background:transparent;border-radius:0;font-family:var(--mono);font-size:13.5px;padding:12px 18px}
.input-group input:focus-visible{outline:none}
.icon-btn{display:inline-grid;place-items:center;width:48px;flex:none;border:0;border-left:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;transition:all 0.2s}
.icon-btn:hover{background:var(--accent-soft);color:var(--accent)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:22px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:12px 24px;border-radius:12px;border:1px solid transparent;font-weight:700;cursor:pointer;white-space:nowrap;transition:all 0.25s cubic-bezier(0.4, 0, 0.2, 1);position:relative;overflow:hidden}
.btn::after{content:'';position:absolute;inset:0;background:rgba(255,255,255,0.1);opacity:0;transition:opacity 0.2s}
.btn:hover::after{opacity:1}
.btn-sm{padding:8px 16px;font-size:13px}
.btn-primary{background:var(--accent);color:var(--accent-ink);box-shadow:0 4px 20px rgba(46,160,67,0.35)}
.btn-primary:hover{background:var(--accent-hover);transform:translateY(-2px);box-shadow:0 6px 25px rgba(46,160,67,0.5)}
.btn-secondary{background:var(--surface-2);color:var(--text);border-color:var(--border)}
.btn-secondary:hover{background:var(--border);border-color:var(--border-strong);transform:translateY(-2px)}
.btn-danger-ghost{background:transparent;color:var(--danger);border-color:var(--border)}
.btn-danger-ghost:hover{background:var(--danger-soft);border-color:var(--danger);transform:translateY(-2px)}

.seg{display:inline-flex;padding:5px;gap:6px;background:var(--bg);border:1px solid var(--border);border-radius:14px;margin-bottom:28px}
.seg button{border:0;background:transparent;padding:9px 20px;border-radius:10px;font-weight:700;color:var(--muted);cursor:pointer;transition:all 0.25s}
.seg button:hover{color:var(--text)}
.seg button.active{background:var(--surface-2);color:var(--text);box-shadow:var(--shadow);border:1px solid var(--border)}

.templates-bar{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.template-chip{background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:8px 14px;border-radius:10px;font-size:12.5px;font-weight:700;cursor:pointer;transition:all 0.25s;box-shadow:var(--shadow)}
.template-chip:hover{border-color:var(--accent);background:var(--accent-soft);color:var(--accent);transform:translateY(-2px)}

.url-bar{display:grid;grid-template-columns:140px minmax(0,1fr) auto;gap:14px;margin-bottom:28px}
.url-bar select{font-weight:800}
.url-bar input{font-family:var(--mono);font-size:13.5px}
.header-row{display:grid;grid-template-columns:1fr 1fr 48px;gap:14px;margin-bottom:14px}
.header-row .icon-btn{border:1px solid var(--border);border-radius:12px}
.hint{margin:14px 0 0;color:var(--muted);font-size:13.5px}
.hint b{color:var(--text);font-weight:700}

.tag{font-family:var(--mono);font-weight:800;font-size:13.5px;letter-spacing:0.4px;text-align:center;cursor:default;border:1px solid;user-select:all}
.tag-blue{color:var(--info);background:var(--info-soft);border-color:rgba(88,166,255,0.3)}
.tag-violet{color:#bc8cff;background:rgba(188,140,255,0.15);border-color:rgba(188,140,255,0.3)}
.tag-amber{color:var(--warn);background:var(--warn-soft);border-color:rgba(210,153,34,0.3)}
.tag-green{color:var(--ok);background:var(--ok-soft);border-color:rgba(63,185,80,0.3)}

.auth-row{display:grid;grid-template-columns:190px 140px minmax(0,1fr);gap:16px;align-items:end;margin-bottom:18px}
.auth-row.two{grid-template-columns:190px minmax(0,1fr)}
.auth-row.opt{grid-template-columns:150px 190px minmax(0,1fr)}
.auth-row .field{margin-bottom:0}
.note-cell{padding:12px 0;color:var(--muted);font-size:13.5px}
.note-cell code{font-family:var(--mono);color:var(--text);background:var(--bg);padding:3px 8px;border-radius:6px;border:1px solid var(--border)}
.opt-title{margin:28px 0 14px;font-size:11.5px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
.panel-actions{margin:6px 0 8px}

.toolbar{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.toolbar .seg{margin:0}
.spacer{flex:1}

.log{background:var(--surface);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);margin-bottom:18px;overflow:hidden;transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);animation: logSlide 0.4s ease}
@keyframes logSlide{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.log:hover{border-color:var(--border-strong);box-shadow:var(--shadow-lg)}
.log-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:20px 26px}
.log-title{display:flex;align-items:center;gap:12px;flex-wrap:wrap;min-width:0}
.log-id{font-family:var(--mono);font-size:13.5px;font-weight:700}
.log-meta{color:var(--muted);font-size:13px}
.log-actions{display:flex;align-items:center;gap:16px}
.log-url{padding:0 26px 16px;font-family:var(--mono);font-size:13px;color:var(--muted);word-break:break-all}
.log details{border-top:1px solid var(--border)}
.log summary{padding:16px 26px;cursor:pointer;color:var(--muted);font-size:13.5px;font-weight:600;user-select:none;transition:color 0.2s}
.log summary:hover{color:var(--text)}
.block{padding:0 26px 22px}
.block-label{margin-bottom:9px;font-size:11.5px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}
pre{margin:0;padding:20px;background:var(--bg);border:1px solid var(--border);border-radius:14px;font:13.5px/1.65 var(--mono);overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-word;box-shadow:inset 0 2px 6px rgba(0,0,0,0.6)}
.trunc{margin-top:10px;font-size:13px;color:var(--warn)}
.badge{display:inline-flex;align-items:center;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:0.4px}
.b-info{background:var(--info-soft);color:var(--info);border:1px solid rgba(88,166,255,0.3)}
.b-ok{background:var(--ok-soft);color:var(--ok);border:1px solid rgba(63,185,80,0.3)}
.b-warn{background:var(--warn-soft);color:var(--warn);border:1px solid rgba(210,153,34,0.3)}
.b-err{background:var(--danger-soft);color:var(--danger);border:1px solid rgba(248,81,73,0.3)}
.b-neutral{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.empty{display:grid;place-items:center;gap:12px;text-align:center;padding:80px 24px;border:1px dashed var(--border);border-radius:18px;color:var(--muted);background:var(--surface)}
.empty .icon{width:36px;height:36px;color:var(--accent)}
.empty strong{color:var(--text);font-size:16px}

.toasts{position:fixed;right:28px;bottom:28px;display:flex;flex-direction:column;gap:12px;z-index:60}
.toast{min-width:280px;max-width:420px;padding:16px 20px;border-radius:14px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:5px solid var(--info);box-shadow:var(--shadow-lg);font-size:14px;animation: toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards}
@keyframes toastIn{from{opacity:0;transform:translateX(30px) scale(0.95)}to{opacity:1;transform:none}}
.toast.success{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--danger)}

.modal{position:fixed;inset:0;background:rgba(1,4,9,0.85);display:grid;place-items:center;padding:24px;z-index:80;backdrop-filter:blur(12px);animation: modalFade 0.3s ease}
@keyframes modalFade{from{opacity:0}to{opacity:1}}
.dialog{width:100%;max-width:460px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:32px;box-shadow:var(--shadow-lg);animation: dialogPopup 0.4s cubic-bezier(0.16, 1, 0.3, 1)}
@keyframes dialogPopup{from{opacity:0;transform:scale(0.9) translateY(20px)}to{opacity:1;transform:none}}
.dialog h3{margin:0 0 12px;font-size:20px;font-weight:800}
.dialog p{margin:0 0 28px;color:var(--muted);font-size:14px}
.dialog .actions{display:flex;justify-content:flex-end;gap:14px}

@media (max-width:900px){
  .app{grid-template-columns:1fr}
  .sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:14px;padding:18px}
  .brand{padding:0}.nav-label,.side-foot{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .main{padding:28px 18px 64px}
  .grid-2,.url-bar,.metrics-bar{grid-template-columns:1fr}
  .topbar{flex-direction:column}
}
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
      <div><strong>NexRelay</strong><span>Matrix Hub</span></div>
    </div>
    <div class="nav-label">Navigation</div>
    <nav class="nav" aria-label="Primary">
      <button type="button" class="nav-item active" data-panel="inbound" data-route="/hub/inbound"><svg class="icon"><use href="#i-in"/></svg>Inbound Webhook</button>
      <button type="button" class="nav-item" data-panel="outbound" data-route="/hub/outbound"><svg class="icon"><use href="#i-out"/></svg>Outbound Client</button>
      <button type="button" class="nav-item" data-panel="logs" data-route="/hub/logs"><svg class="icon"><use href="#i-list"/></svg>Execution Logs<span class="count" id="logCount">0</span></button>
    </nav>
    <div class="side-foot">
      <div class="lbl">Matrix Mode</div>
      <div>Unified secret-free webhook listener active.</div>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div><h1 id="pageTitle"></h1><p id="pageSub"></p></div>
      <div class="status" id="statusPill"><span class="dot"></span><span id="statusText">Checking gateway…</span></div>
    </header>

    <!-- Telemetry Bar -->
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
        <div class="label">Security State</div>
        <div class="value" id="metricSession">Secured</div>
      </div>
    </div>

    <!-- Inbound Panel -->
    <section id="panel-inbound" class="panel active">
      <div class="card">
        <div class="card-head"><div><h2>Inbound Webhook Endpoint URL</h2><p>Pristine, secret-free URL route. Zero tokens or keys exposed in query parameters.</p></div></div>
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
          <div><h2>Authentication Credentials</h2><p>Cryptographically secure tokens rotating on demand. Strictly transmitted via HTTP headers.</p></div>
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
                  <input type="password" id="bearerBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
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
                  <input type="text" id="basicUserBox" readonly spellcheck="false" placeholder="Loading…">
                  <button type="button" class="icon-btn" data-copy="basicUserBox" data-label="Username" title="Copy" aria-label="Copy username"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="field">
                <label for="basicPassBox">Password</label>
                <div class="input-group">
                  <input type="password" id="basicPassBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
                  <button type="button" class="icon-btn" data-reveal="basicPassBox" title="Show / hide" aria-label="Show or hide password"><svg class="icon"><use href="#i-eye"/></svg></button>
                  <button type="button" class="icon-btn" data-copy="basicPassBox" data-label="Password" title="Copy" aria-label="Copy password"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="hint">In ServiceNow, set REST Message Authentication type to <b>Basic</b>.</p>
          </div>

          <!-- API Key -->
          <div class="tab-panel" data-panel-group="cred" id="cred-key" hidden>
            <div class="field">
              <label for="apiKeyBox">API Key</label>
              <div class="input-group">
                <input type="password" id="apiKeyBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
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
                  <input type="text" id="oauthIdBox" readonly spellcheck="false" placeholder="Loading…">
                  <button type="button" class="icon-btn" data-copy="oauthIdBox" data-label="Client ID" title="Copy" aria-label="Copy client ID"><svg class="icon"><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="field">
                <label for="oauthSecretBox">Client Secret</label>
                <div class="input-group">
                  <input type="password" id="oauthSecretBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
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
        <div class="card-body"><pre id="curlBox">Loading credentials…</pre></div>
      </div>
    </section>

    <!-- Outbound Panel -->
    <section id="panel-outbound" class="panel">
      <div class="card">
        <div class="card-head">
          <div><h2>ServiceNow Request Builder</h2><p>Execute authenticated requests against your PDI or ServiceNow tables with built-in templates.</p></div>
        </div>
        <div class="card-body">
          <div class="templates-bar">
            <span style="font-size: 11.5px; font-weight: 800; color: var(--muted); align-self: center; text-transform: uppercase;">Templates:</span>
            <button type="button" class="template-chip" data-template="incident-post">+ Create Incident</button>
            <button type="button" class="template-chip" data-template="incident-get">+ Query Incidents</button>
            <button type="button" class="template-chip" data-template="user-get">+ Get Users</button>
            <button type="button" class="template-chip" data-template="ping">+ Health Check</button>
          </div>

          <div class="url-bar">
            <select id="httpMethod" aria-label="HTTP method">
              <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
            </select>
            <input type="url" id="httpUrl" placeholder="https://dev_instance.service-now.com/api/now/table/incident" spellcheck="false" aria-label="Request URL">
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
  "short_description": "Automated incident created via Matrix Command Center",
  "urgency": "2",
  "impact": "2",
  "category": "software"
}</textarea>
          </div>
        </div>
      </div>
    </section>

    <!-- Logs Panel -->
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

  var API = '/api/servicenow';
  var MAX_RENDER_CHARS = 50000;
  var PAGES = {
    inbound: ['Inbound Webhook Hub', 'Receive ServiceNow payloads on a clean, secret-free endpoint URL.'],
    outbound: ['Outbound HTTP Client', 'Send authenticated requests to your ServiceNow instance.'],
    logs: ['Execution Logs & Audit', 'Real-time audit trail of inbound and outbound traffic.']
  };
  var state = { creds: null, credTab: 'cred-bearer', seen: {}, primed: false, inbound: [], outbound: [], filter: 'all', sending: false, sig: '', open: {} };

  function $(id) { return document.getElementById(id); }
  function esc(v) {
    return String(v === undefined || v === null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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

  function showPanel(name, pushHistory) {
    Array.prototype.forEach.call(document.querySelectorAll('.panel'), function (p) {
      p.classList.toggle('active', p.id === 'panel-' + name);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (b) {
      b.classList.toggle('active', b.getAttribute('data-panel') === name);
    });
    if (PAGES[name]) {
      $('pageTitle').textContent = PAGES[name][0];
      $('pageSub').textContent = PAGES[name][1];
    }
    if (pushHistory) {
      history.pushState({ panel: name }, '', '/hub/' + name);
    }
  }

  window.addEventListener('popstate', function() {
    var path = location.pathname;
    if (path.includes('/outbound')) showPanel('outbound', false);
    else if (path.includes('/logs')) showPanel('logs', false);
    else showPanel('inbound', false);
  });

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

  function renderCredentials() {
    var base = location.origin + API;
    $('inboundUrlBox').value = base + '/inbound';
    $('oauthUrlBox').value = base + '/oauth/token';
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
    if (!c) { box.textContent = 'Loading credentials…'; return; }
    var url = $('inboundUrlBox').value;
    var tail = "  -H 'Content-Type: application/json' \\\n" +
      "  -d '{\"short_description\":\"Test payload from NexRelay Matrix\"}'";
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

  function fetchCredentials() {
    return fetch(API + '/credentials', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (c) { state.creds = c; renderCredentials(); })
      .catch(function (e) { toast('Could not load credentials: ' + e.message, 'error'); });
  }

  function rotateCredentials() {
    return fetch(API + '/credentials/rotate', { method: 'POST' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (c) {
        state.creds = c;
        renderCredentials();
        toast('New credentials issued securely. Previous keys revoked.', 'success');
      }).catch(function (e) {
        toast('Could not rotate credentials: ' + e.message, 'error');
      });
  }

  function signature(inb, out) {
    return (inb[0] ? inb[0].id : '') + '|' + (out[0] ? out[0].id : '') + '|' + inb.length + '|' + out.length;
  }

  function updateMetrics() {
    var all = state.outbound.concat(state.inbound);
    $('metricTotal').textContent = all.length;

    var successes = state.outbound.filter(function(o) { return o.statusCode >= 200 && o.statusCode < 300; }).length;
    var outboundTotal = state.outbound.length;
    var successRate = outboundTotal > 0 ? Math.round((successes / outboundTotal) * 100) : 100;
    $('metricSuccess').textContent = successRate + '%';

    var totalLatency = state.outbound.reduce(function(acc, o) { return acc + (o.durationMs || 0); }, 0);
    var avgLatency = outboundTotal > 0 ? Math.round(totalLatency / outboundTotal) : 0;
    $('metricLatency').textContent = avgLatency + ' ms';
  }

  function loadLogs() {
    if (document.hidden) return;
    fetch(API + '/logs', { cache: 'no-store' })
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
        '<strong>No records captured</strong><span>Inbound webhooks and outbound requests will appear here instantly.</span></div>';
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
      message: 'Record ' + id + ' will be permanently purged.',
      confirmLabel: 'Delete record', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs/' + encodeURIComponent(id), { method: 'DELETE' })
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
      message: 'All ' + total + ' records will be permanently wiped.',
      confirmLabel: 'Delete all', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs', { method: 'DELETE' })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
        .then(function (d) {
          state.inbound = []; state.outbound = []; state.open = {};
          resetSignature(); renderLogs(); updateMetrics();
          toast(d.deleted + ' records wiped', 'success');
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

  function loadTemplate(type) {
    var urlInput = $('httpUrl');
    var methodInput = $('httpMethod');
    var bodyInput = $('httpBody');
    
    if (type === 'incident-post') {
      methodInput.value = 'POST';
      urlInput.value = 'https://dev_instance.service-now.com/api/now/table/incident';
      bodyInput.value = JSON.stringify({
        short_description: "Automated incident created via Matrix Command Center",
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
      headers: { 'Content-Type': 'application/json' },
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
        showPanel('logs', true);
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
    $('statusText').textContent = ok ? 'Gateway online' : 'Gateway offline';
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
      if (!state.creds) { toast('Credentials still loading', 'error'); return; }
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
    if ((el = t.closest('[data-panel]'))) { showPanel(el.getAttribute('data-panel'), true); return; }
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

  $('rotateBtn').addEventListener('click', rotateCredentials);
  $('clearAllBtn').addEventListener('click', deleteAll);
  $('sendBtn').addEventListener('click', sendOutbound);
  $('addHeaderBtn').addEventListener('click', function () { addHeaderRow('', ''); });
  $('authType').addEventListener('change', updateAuthFields);
  $('httpMethod').addEventListener('change', updateBodyState);

  addHeaderRow('Accept', 'application/json');
  updateAuthFields();
  updateBodyState();

  var initPath = location.pathname;
  if (initPath.includes('/outbound')) showPanel('outbound', false);
  else if (initPath.includes('/logs')) showPanel('logs', false);
  else { showPanel('inbound', false); history.replaceState({ panel: 'inbound' }, '', '/hub/inbound'); }

  renderCredentials();
  renderLogs();
  updateMetrics();
  fetchCredentials();
  loadLogs();
  checkHealth();
  setInterval(loadLogs, 3000);
  setInterval(checkHealth, 30000);
})();
</script>
</body>
</html>`;

app.get(['/', '/hub', '/hub/inbound', '/hub/outbound', '/hub/logs'], (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.type('html').send(PAGE);
});

app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({ status: 'Error', message: 'Invalid JSON body syntax.' });
    }
    console.error(err);
    res.status(500).json({ status: 'Error', message: 'Internal server error.' });
});

app.listen(PORT, () => {
    console.log(`NexRelay Matrix Edition running on port ${PORT}`);
});