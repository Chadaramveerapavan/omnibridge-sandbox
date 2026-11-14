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

app.all('/api/servicenow/inbound', (req, res) => {
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
        method: req.method,
        authMethod,
        timestamp: new Date().toISOString(),
        headers: { 'content-type': req.headers['content-type'] },
        query: req.query,
        payload: req.body
    };

    addLog(globalStore.inbound, inboundEntry);
    res.status(200).json({ status: 'Success', message: `Inbound ${req.method} request successfully ingested.`, record: inboundEntry });
});

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

// ---- Interactive SpiderWeb Nexus Frontend ----
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexRelay · SpiderWeb Nexus</title>
<style>
:root{
  --bg:#02040a;--surface:#0a0e1a;--surface-2:#111729;--border:#1e293b;--border-strong:#334155;
  --text:#f8fafc;--muted:#94a3b8;--accent:#10b981;--accent-hover:#059669;--accent-ink:#ffffff;--accent-soft:rgba(16,185,129,0.14);
  --cyan:#06b6d4;--cyan-soft:rgba(6,182,212,0.14);--violet:#8b5cf6;--violet-soft:rgba(139,92,246,0.14);
  --danger:#ef4444;--danger-soft:rgba(239,68,68,0.14);--ok:#10b981;--ok-soft:rgba(16,185,129,0.14);
  --warn:#f59e0b;--warn-soft:rgba(245,158,11,0.14);--info:#38bdf8;--info-soft:rgba(56,189,248,0.14);
  --shadow:0 16px 36px rgba(0,0,0,0.75);
  --shadow-lg:0 28px 70px rgba(0,0,0,0.9), 0 0 32px rgba(16,185,129,0.15);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
[hidden]{display:none!important}
button{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* Interactive SpiderWeb Canvas */
#webCanvas{
  position:fixed;inset:0;width:100vw;height:100vh;z-index:0;pointer-events:none;
  background:radial-gradient(circle at 50% 45%, #091326 0%, #02040a 75%);
}

/* Warp Illusion Overlay */
#warpFlash{
  position:fixed;inset:0;z-index:100;pointer-events:none;opacity:0;
  background:radial-gradient(circle at var(--wx, 50%) var(--wy, 50%), rgba(16,185,129,0.35), rgba(6,182,212,0.15) 35%, rgba(2,4,10,0.96) 75%);
  transition:opacity 0.25s ease;
}
#warpFlash.active{opacity:1}

/* ==================== SPIDERWEB HOMEPAGE ==================== */
.home-view{
  position:relative;z-index:10;min-height:100vh;display:flex;flex-direction:column;justify-content:space-between;
  padding:28px 48px 36px;transition:transform 0.6s cubic-bezier(0.7, 0, 0.2, 1), opacity 0.5s ease, filter 0.5s ease;
}
.home-view.diving{
  transform:scale(1.65);opacity:0;filter:blur(8px);pointer-events:none;
}
.home-view.entering{
  animation:homeUnwarp 0.65s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes homeUnwarp{
  from{transform:scale(1.4);opacity:0;filter:blur(6px)}
  to{transform:scale(1);opacity:1;filter:blur(0)}
}

.home-nav{display:flex;align-items:center;justify-content:space-between;max-width:1280px;width:100%;margin:0 auto}
.home-brand{display:flex;align-items:center;gap:14px}
.home-logo{
  width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#10b981,#06b6d4);
  display:grid;place-items:center;color:#fff;box-shadow:0 0 24px rgba(16,185,129,0.45);
}
.home-brand strong{font-size:19px;letter-spacing:0.4px;display:block;line-height:1.1}
.home-brand span{font-size:11px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase;color:var(--accent)}

.home-hero{
  max-width:1180px;width:100%;margin:auto;text-align:center;padding:32px 0;
}
.nexus-pill{
  display:inline-flex;align-items:center;gap:10px;padding:7px 18px;border-radius:999px;
  background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.35);
  color:#6ee7b7;font-size:12px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;
  margin-bottom:24px;backdrop-filter:blur(10px);
}
.nexus-pill .pulse{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent);animation:pulseDot 2s infinite}
@keyframes pulseDot{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:0.5}}

.hero-title{
  margin:0 auto 18px;font-size:clamp(38px, 6vw, 68px);font-weight:900;letter-spacing:-1.5px;line-height:1.06;
  background:linear-gradient(135deg, #ffffff 25%, #6ee7b7 60%, #38bdf8 95%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  text-shadow:0 12px 40px rgba(16,185,129,0.18);
}
.hero-sub{
  max-width:640px;margin:0 auto 48px;color:var(--muted);font-size:16.5px;line-height:1.65;
}

/* Spiderweb Portal Cards */
.portal-grid{
  display:grid;grid-template-columns:repeat(3, 1fr);gap:24px;text-align:left;
}
.portal-card{
  position:relative;background:rgba(10,14,26,0.72);border:1px solid rgba(51,65,85,0.65);
  border-radius:22px;padding:30px 28px;cursor:pointer;backdrop-filter:blur(16px);
  transition:all 0.35s cubic-bezier(0.16, 1, 0.3, 1);overflow:hidden;
  display:flex;flex-direction:column;justify-content:space-between;min-height:245px;
  box-shadow:0 20px 45px rgba(0,0,0,0.6);
}
.portal-card::before{
  content:'';position:absolute;inset:0;border-radius:22px;padding:1.5px;
  background:linear-gradient(135deg, rgba(16,185,129,0.6), rgba(6,182,212,0.2), transparent 65%);
  -webkit-mask:linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;opacity:0.4;transition:opacity 0.35s;
}
.portal-card:hover{
  transform:translateY(-8px) scale(1.02);
  border-color:rgba(16,185,129,0.7);
  background:rgba(15,23,42,0.88);
  box-shadow:0 28px 60px rgba(0,0,0,0.85), 0 0 35px rgba(16,185,129,0.25);
}
.portal-card:hover::before{opacity:1}

.portal-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.portal-icon{
  width:48px;height:48px;border-radius:14px;display:grid;place-items:center;
  background:var(--accent-soft);color:var(--accent);border:1px solid rgba(16,185,129,0.3);
  transition:transform 0.35s ease, background 0.35s ease;
}
.portal-card[data-portal="outbound"] .portal-icon{background:var(--cyan-soft);color:var(--cyan);border-color:rgba(6,182,212,0.3)}
.portal-card[data-portal="logs"] .portal-icon{background:var(--violet-soft);color:var(--violet);border-color:rgba(139,92,246,0.3)}
.portal-card:hover .portal-icon{transform:scale(1.1) rotate(-4deg)}
.portal-icon .icon{width:22px;height:22px}

.portal-tag{
  font-family:var(--mono);font-size:11px;font-weight:800;padding:4px 10px;border-radius:999px;
  background:rgba(255,255,255,0.05);border:1px solid var(--border);color:var(--muted);
}
.portal-card h3{margin:0 0 8px;font-size:20px;font-weight:800;color:var(--text)}
.portal-card p{margin:0 0 22px;font-size:13.5px;color:var(--muted);line-height:1.55}
.portal-cta{
  display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:800;
  color:var(--accent);letter-spacing:0.3px;transition:gap 0.25s;
}
.portal-card[data-portal="outbound"] .portal-cta{color:var(--cyan)}
.portal-card[data-portal="logs"] .portal-cta{color:#a78bfa}
.portal-card:hover .portal-cta{gap:13px}

.home-footer{
  max-width:1280px;width:100%;margin:0 auto;display:flex;align-items:center;justify-content:space-between;
  padding-top:20px;border-top:1px solid rgba(30,41,59,0.6);color:var(--muted);font-size:12.5px;
}
.home-stats{display:flex;gap:24px;font-family:var(--mono)}
.home-stats b{color:var(--text)}

/* ==================== WORKSPACE SHELL ==================== */
.app{
  position:relative;z-index:10;display:grid;grid-template-columns:275px minmax(0,1fr);min-height:100vh;
  background:rgba(2,4,10,0.82);backdrop-filter:blur(14px);
}
.app.unwarping{
  animation:appUnwarp 0.65s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes appUnwarp{
  0%{opacity:0;transform:scale(0.84);filter:blur(8px)}
  100%{opacity:1;transform:scale(1);filter:blur(0)}
}

.sidebar{
  background:rgba(10,14,26,0.92);color:var(--muted);display:flex;flex-direction:column;
  padding:28px 18px;position:sticky;top:0;height:100vh;border-right:1px solid var(--border);
}
.brand{display:flex;align-items:center;gap:14px;padding:4px 8px 24px;cursor:pointer}
.brand-mark{
  width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#10b981,#06b6d4);
  display:grid;place-items:center;color:#fff;box-shadow:0 0 22px rgba(16,185,129,0.4);
}
.brand-mark .icon{width:22px;height:22px}
.brand strong{display:block;color:#fff;font-size:17px;letter-spacing:0.3px}
.brand span{font-size:11px;color:var(--accent);font-weight:800;text-transform:uppercase;letter-spacing:1.1px}

.home-return-btn{
  display:flex;align-items:center;gap:10px;width:100%;padding:11px 14px;margin-bottom:22px;
  border:1px solid rgba(16,185,129,0.35);border-radius:12px;background:rgba(16,185,129,0.08);
  color:#6ee7b7;font-weight:700;font-size:13px;cursor:pointer;transition:all 0.25s;
}
.home-return-btn:hover{background:rgba(16,185,129,0.18);transform:translateX(-2px);box-shadow:0 0 20px rgba(16,185,129,0.2)}

.nav{display:flex;flex-direction:column;gap:8px}
.nav-label{font-size:11px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;padding:0 12px 8px;color:var(--muted)}
.nav-item{
  display:flex;align-items:center;gap:12px;width:100%;padding:12px 15px;border:1px solid transparent;border-radius:12px;
  background:transparent;color:var(--muted);font-weight:600;text-align:left;cursor:pointer;transition:all 0.25s;
}
.nav-item:hover{background:rgba(255,255,255,0.04);color:#fff;transform:translateX(4px)}
.nav-item.active{background:var(--surface-2);color:#fff;box-shadow:inset 3px 0 0 var(--accent);border-color:var(--border)}
.count{margin-left:auto;min-width:26px;padding:2px 8px;border-radius:999px;background:var(--ok-soft);color:var(--ok);font-size:11px;font-weight:800;text-align:center}

.side-foot{margin-top:auto;padding:18px 12px 0;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
.side-foot .lbl{text-transform:uppercase;letter-spacing:1px;font-size:10.5px;color:var(--accent);font-weight:800;margin-bottom:4px}

.main{padding:34px 44px 72px;width:100%;max-width:1320px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:28px}
.topbar h1{margin:0;font-size:26px;font-weight:800;letter-spacing:-0.4px;color:var(--text)}
.topbar p{margin:5px 0 0;color:var(--muted);font-size:14px}
.status{display:inline-flex;align-items:center;gap:10px;padding:8px 16px;border:1px solid var(--border);border-radius:999px;background:var(--surface);font-size:12.5px;font-weight:700;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted)}
.status.ok .dot{background:var(--ok);box-shadow:0 0 0 5px var(--ok-soft), 0 0 12px var(--ok)}
.status.bad .dot{background:var(--danger);box-shadow:0 0 0 5px var(--danger-soft), 0 0 12px var(--danger)}

.metrics-bar{display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:28px}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:18px 22px;box-shadow:var(--shadow);transition:all 0.25s}
.metric-card:hover{transform:translateY(-3px);border-color:var(--accent)}
.metric-card .label{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:6px}
.metric-card .value{font-size:22px;font-weight:800;font-family:var(--mono);color:var(--text)}

.panel{display:none}
.panel.active{display:block;animation:panelReveal 0.45s cubic-bezier(0.16, 1, 0.3, 1) forwards}
@keyframes panelReveal{from{opacity:0;transform:scale(0.97) translateY(12px)}to{opacity:1;transform:none}}

.card{background:var(--surface);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);margin-bottom:24px;overflow:hidden}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 26px;border-bottom:1px solid var(--border);background:var(--surface-2)}
.card-head h2{margin:0;font-size:17px;font-weight:750}
.card-head p{margin:4px 0 0;color:var(--muted);font-size:13px}
.card-body{padding:26px}

label{display:block;margin-bottom:8px;font-size:11.5px;font-weight:800;color:var(--muted);letter-spacing:0.8px;text-transform:uppercase}
.field{margin-bottom:20px}
.field:last-child{margin-bottom:0}
input,select,textarea{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:12px;padding:11px 16px;font:inherit;transition:all 0.2s}
textarea{font-family:var(--mono);font-size:13.5px;resize:vertical;min-height:170px}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft);outline:none}
.input-group{display:flex;align-items:stretch;border:1px solid var(--border);border-radius:12px;background:var(--bg);overflow:hidden}
.input-group:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.input-group input{border:0;background:transparent;border-radius:0;font-family:var(--mono);font-size:13.5px;padding:11px 16px}
.input-group input:focus-visible{outline:none}
.icon-btn{display:inline-grid;place-items:center;width:46px;flex:none;border:0;border-left:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;transition:all 0.2s}
.icon-btn:hover{background:var(--accent-soft);color:var(--accent)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:11px 22px;border-radius:12px;border:1px solid transparent;font-weight:700;cursor:pointer;white-space:nowrap;transition:all 0.25s}
.btn-sm{padding:8px 15px;font-size:13px}
.btn-primary{background:var(--accent);color:var(--accent-ink);box-shadow:0 4px 18px rgba(16,185,129,0.3)}
.btn-primary:hover{background:var(--accent-hover);transform:translateY(-2px)}
.btn-secondary{background:var(--surface-2);color:var(--text);border-color:var(--border)}
.btn-secondary:hover{background:var(--border);transform:translateY(-2px)}
.btn-danger-ghost{background:transparent;color:var(--danger);border-color:var(--border)}
.btn-danger-ghost:hover{background:var(--danger-soft);border-color:var(--danger)}

.seg{display:inline-flex;padding:5px;gap:6px;background:var(--bg);border:1px solid var(--border);border-radius:14px;margin-bottom:24px}
.seg button{border:0;background:transparent;padding:8px 18px;border-radius:10px;font-weight:700;color:var(--muted);cursor:pointer;transition:all 0.2s}
.seg button:hover{color:var(--text)}
.seg button.active{background:var(--surface-2);color:var(--text);border:1px solid var(--border)}

.templates-bar{display:flex;gap:10px;margin-bottom:22px;flex-wrap:wrap}
.template-chip{background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:7px 13px;border-radius:10px;font-size:12.5px;font-weight:700;cursor:pointer;transition:all 0.2s}
.template-chip:hover{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}

.url-bar{display:grid;grid-template-columns:130px minmax(0,1fr) auto;gap:12px;margin-bottom:24px}
.url-bar select{font-weight:800}
.url-bar input{font-family:var(--mono);font-size:13.5px}
.header-row{display:grid;grid-template-columns:1fr 1fr 46px;gap:12px;margin-bottom:12px}
.header-row .icon-btn{border:1px solid var(--border);border-radius:12px}
.hint{margin:14px 0 0;color:var(--muted);font-size:13px}
.hint b{color:var(--text)}

.tag{font-family:var(--mono);font-weight:800;font-size:13px;text-align:center;cursor:default;border:1px solid;user-select:all}
.tag-blue{color:var(--info);background:var(--info-soft);border-color:rgba(56,189,248,0.3)}
.tag-violet{color:#a78bfa;background:var(--violet-soft);border-color:rgba(139,92,246,0.3)}
.tag-amber{color:var(--warn);background:var(--warn-soft);border-color:rgba(245,158,11,0.3)}
.tag-green{color:var(--ok);background:var(--ok-soft);border-color:rgba(16,185,129,0.3)}

.auth-row{display:grid;grid-template-columns:180px 130px minmax(0,1fr);gap:14px;align-items:end;margin-bottom:16px}
.auth-row.two{grid-template-columns:180px minmax(0,1fr)}
.auth-row.opt{grid-template-columns:145px 180px minmax(0,1fr)}
.auth-row .field{margin-bottom:0}
.note-cell{padding:11px 0;color:var(--muted);font-size:13px}
.opt-title{margin:24px 0 12px;font-size:11px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
.panel-actions{margin:6px 0 8px}

.toolbar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.spacer{flex:1}

.log{background:var(--surface);border:1px solid var(--border);border-radius:16px;box-shadow:var(--shadow);margin-bottom:16px;overflow:hidden}
.log-head{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;padding:18px 24px}
.log-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.log-id{font-family:var(--mono);font-size:13px;font-weight:700}
.log-meta{color:var(--muted);font-size:12.5px}
.log-actions{display:flex;align-items:center;gap:14px}
.log-url{padding:0 24px 14px;font-family:var(--mono);font-size:12.5px;color:var(--muted);word-break:break-all}
.log details{border-top:1px solid var(--border)}
.log summary{padding:14px 24px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:600;user-select:none}
.log summary:hover{color:var(--text)}
.block{padding:0 24px 20px}
.block-label{margin-bottom:8px;font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}
pre{margin:0;padding:18px;background:var(--bg);border:1px solid var(--border);border-radius:12px;font:13px/1.6 var(--mono);overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-word}
.badge{display:inline-flex;align-items:center;padding:3px 11px;border-radius:999px;font-size:11.5px;font-weight:800}
.b-info{background:var(--info-soft);color:var(--info);border:1px solid rgba(56,189,248,0.3)}
.b-ok{background:var(--ok-soft);color:var(--ok);border:1px solid rgba(16,185,129,0.3)}
.b-warn{background:var(--warn-soft);color:var(--warn);border:1px solid rgba(245,158,11,0.3)}
.b-err{background:var(--danger-soft);color:var(--danger);border:1px solid rgba(239,68,68,0.3)}
.b-neutral{background:var(--bg);color:var(--muted);border:1px solid var(--border)}
.empty{display:grid;place-items:center;gap:10px;text-align:center;padding:70px 24px;border:1px dashed var(--border);border-radius:18px;color:var(--muted);background:var(--surface)}
.empty .icon{width:34px;height:34px;color:var(--accent)}
.empty strong{color:var(--text);font-size:16px}

.toasts{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:10px;z-index:120}
.toast{min-width:270px;max-width:400px;padding:14px 18px;border-radius:12px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--info);box-shadow:var(--shadow-lg);font-size:13.5px}
.toast.success{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--danger)}

.modal{position:fixed;inset:0;background:rgba(2,4,10,0.85);display:grid;place-items:center;padding:24px;z-index:130;backdrop-filter:blur(10px)}
.dialog{width:100%;max-width:440px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:28px;box-shadow:var(--shadow-lg)}
.dialog h3{margin:0 0 10px;font-size:19px;font-weight:800}
.dialog p{margin:0 0 24px;color:var(--muted);font-size:14px}
.dialog .actions{display:flex;justify-content:flex-end;gap:12px}

@media (max-width:960px){
  .home-view{padding:20px}
  .portal-grid{grid-template-columns:1fr}
  .app{grid-template-columns:1fr}
  .sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:12px;padding:16px}
  .brand{padding:0}.nav-label,.side-foot{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .main{padding:24px 18px 60px}
  .grid-2,.url-bar,.metrics-bar,.auth-row,.auth-row.two,.auth-row.opt{grid-template-columns:1fr}
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
  <symbol id="i-web" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/><line x1="19.07" y1="4.93" x2="4.93" y2="19.07"/></symbol>
  <symbol id="i-send" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></symbol>
  <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
  <symbol id="i-arrow" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></symbol>
  <symbol id="i-home" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></symbol>
</svg>

<!-- Interactive SpiderWeb Canvas & Warp Flash -->
<canvas id="webCanvas"></canvas>
<div id="warpFlash"></div>

<!-- ==================== HOMEPAGE VIEW ==================== -->
<section id="homeView" class="home-view">
  <header class="home-nav">
    <div class="home-brand">
      <div class="home-logo"><svg class="icon"><use href="#i-web"/></svg></div>
      <div>
        <strong>NexRelay</strong>
        <span>SpiderWeb Nexus</span>
      </div>
    </div>
    <div class="status" id="homeStatusPill"><span class="dot"></span><span id="homeStatusText">Synchronizing web…</span></div>
  </header>

  <div class="home-hero">
    <div class="nexus-pill"><span class="pulse"></span>Bidirectional ServiceNow Integration Mesh</div>
    <h1 class="hero-title">NexRelay · SpiderWeb Nexus</h1>
    <p class="hero-sub">Move your cursor across the neural silk web, then select any node below to dive directly into your ServiceNow integration workspace.</p>

    <div class="portal-grid">
      <article class="portal-card" data-portal="inbound" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-in"/></svg></div>
            <span class="portal-tag">ALL METHODS</span>
          </div>
          <h3>Inbound Webhook Hub</h3>
          <p>Capture ServiceNow GET, POST, PUT, PATCH, and DELETE payloads on a pristine, secret-free URL with multi-auth verification.</p>
        </div>
        <div class="portal-cta">Dive into Inbound Hub <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>

      <article class="portal-card" data-portal="outbound" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-out"/></svg></div>
            <span class="portal-tag">REST CLIENT</span>
          </div>
          <h3>Outbound PDI Client</h3>
          <p>Dispatch authenticated Table API calls directly to your ServiceNow instance using Basic, OAuth 2.0 Bearer, or custom headers.</p>
        </div>
        <div class="portal-cta">Dive into Outbound Client <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>

      <article class="portal-card" data-portal="logs" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-list"/></svg></div>
            <span class="portal-tag" id="homeLogBadge">0 EVENTS</span>
          </div>
          <h3>Live Execution Logs</h3>
          <p>Inspect real-time request headers, query parameters, JSON payloads, response codes, and latency telemetry across the mesh.</p>
        </div>
        <div class="portal-cta">Dive into Audit Stream <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>
    </div>
  </div>

  <footer class="home-footer">
    <div>Click any portal node to trigger a 3D warp dive into the web.</div>
    <div class="home-stats">
      <span>TRAFFIC: <b id="homeStatTotal">0</b></span>
      <span>UPTIME: <b id="homeStatUptime">0s</b></span>
    </div>
  </footer>
</section>

<!-- ==================== WORKSPACE VIEW ==================== -->
<div id="workspaceView" class="app" hidden>
  <aside class="sidebar">
    <div class="brand" id="brandHomeBtn" title="Return to SpiderWeb Homepage">
      <div class="brand-mark"><svg class="icon"><use href="#i-web"/></svg></div>
      <div><strong>NexRelay</strong><span>SpiderWeb Nexus</span></div>
    </div>

    <button type="button" class="home-return-btn" id="returnHomeBtn">
      <svg class="icon"><use href="#i-home"/></svg>SpiderWeb Home
    </button>

    <div class="nav-label">Workspace Nodes</div>
    <nav class="nav" aria-label="Primary">
      <button type="button" class="nav-item active" data-panel="inbound"><svg class="icon"><use href="#i-in"/></svg>Inbound Webhook</button>
      <button type="button" class="nav-item" data-panel="outbound"><svg class="icon"><use href="#i-out"/></svg>Outbound Client</button>
      <button type="button" class="nav-item" data-panel="logs"><svg class="icon"><use href="#i-list"/></svg>Execution Logs<span class="count" id="logCount">0</span></button>
    </nav>
    <div class="side-foot">
      <div class="lbl">Mesh Status</div>
      <div>Universal listener active (All HTTP Methods).</div>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div><h1 id="pageTitle"></h1><p id="pageSub"></p></div>
      <div class="status" id="statusPill"><span class="dot"></span><span id="statusText">Checking gateway…</span></div>
    </header>

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
        <div class="card-head"><div><h2>Inbound Webhook Endpoint URL</h2><p>Pristine, secret-free URL route supporting GET, POST, PUT, PATCH, and DELETE methods.</p></div></div>
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
  "short_description": "Automated incident created via SpiderWeb Nexus",
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
          <button type="button" class="filter-btn" data-filter="inbound">Inbound</button>
          <button type="button" class="filter-btn" data-filter="outbound">Outbound</button>
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
  var state = {
    view: 'home',
    panel: 'inbound',
    creds: null,
    credTab: 'cred-bearer',
    inbound: [],
    outbound: [],
    filter: 'all',
    sending: false,
    sig: '',
    open: {},
    warping: false
  };

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

  /* ==================== 3D SPIDERWEB & WARP ILLUSION ENGINE ==================== */
  var canvas = $('webCanvas');
  var ctx = canvas.getContext('2d');
  var W = 0, H = 0;
  var mouse = { x: -9999, y: -9999, active: false };
  var warp = { active: false, speed: 1, targetX: 0, targetY: 0, progress: 0 };
  var nodes = [];
  var NODE_COUNT = 85;

  function resizeCanvas() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();

  function initWebNodes() {
    nodes = [];
    for (var i = 0; i < NODE_COUNT; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        z: 0.2 + Math.random() * 0.8,
        vx: (Math.random() - 0.5) * 0.55,
        vy: (Math.random() - 0.5) * 0.55,
        r: 1.5 + Math.random() * 2.2
      });
    }
  }
  initWebNodes();

  window.addEventListener('mousemove', function (e) {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
  });
  window.addEventListener('mouseleave', function () {
    mouse.active = false;
  });

  function renderWebLoop() {
    ctx.clearRect(0, 0, W, H);

    var cx = warp.active ? warp.targetX : W * 0.5;
    var cy = warp.active ? warp.targetY : H * 0.45;

    // Subtle geometric spiderweb rings anchored at center
    var ringCount = 5;
    var maxRadius = Math.max(W, H) * 0.62;
    var scaleBoost = warp.active ? (1 + warp.progress * 3.5) : 1;

    ctx.save();
    ctx.strokeStyle = warp.active ? 'rgba(16, 185, 129, 0.22)' : 'rgba(56, 189, 248, 0.065)';
    ctx.lineWidth = 1;

    // Radial spokes
    var spokes = 16;
    for (var s = 0; s < spokes; s++) {
      var ang = (s / spokes) * Math.PI * 2 + (warp.progress * 0.25);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(ang) * maxRadius * scaleBoost, cy + Math.sin(ang) * maxRadius * scaleBoost);
      ctx.stroke();
    }

    // Concentric web silk polygons
    for (var r = 1; r <= ringCount; r++) {
      var rad = (r / ringCount) * maxRadius * scaleBoost;
      ctx.beginPath();
      for (var s2 = 0; s2 <= spokes; s2++) {
        var a2 = (s2 / spokes) * Math.PI * 2 + (warp.progress * 0.25);
        var wobble = Math.sin(a2 * 3 + r) * 8;
        var px = cx + Math.cos(a2) * (rad + wobble);
        var py = cy + Math.sin(a2) * (rad + wobble);
        if (s2 === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.stroke();
    }
    ctx.restore();

    // Update & draw floating web nodes
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];

      if (warp.active) {
        // Accelerate nodes outward from focal dive point for 3D tunnel illusion
        var dx = n.x - warp.targetX;
        var dy = n.y - warp.targetY;
        var dist = Math.hypot(dx, dy) || 1;
        var pull = (12 + warp.progress * 42) * n.z;
        var prevX = n.x;
        var prevY = n.y;
        n.x += (dx / dist) * pull;
        n.y += (dy / dist) * pull;

        // Draw streak line
        ctx.beginPath();
        ctx.strokeStyle = 'rgba(110, 231, 183, ' + (0.35 + warp.progress * 0.5) + ')';
        ctx.lineWidth = 1.8 * n.z;
        ctx.moveTo(prevX, prevY);
        ctx.lineTo(n.x, n.y);
        ctx.stroke();

        // Respawn near center if flown offscreen during dive
        if (n.x < -50 || n.x > W + 50 || n.y < -50 || n.y > H + 50) {
          var spawnAng = Math.random() * Math.PI * 2;
          var spawnDist = 20 + Math.random() * 90;
          n.x = warp.targetX + Math.cos(spawnAng) * spawnDist;
          n.y = warp.targetY + Math.sin(spawnAng) * spawnDist;
        }
      } else {
        n.x += n.vx * n.z;
        n.y += n.vy * n.z;

        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;

        // Subtle cursor attraction
        if (mouse.active) {
          var mdx = mouse.x - n.x;
          var mdy = mouse.y - n.y;
          var mdist = Math.hypot(mdx, mdy);
          if (mdist < 210 && mdist > 1) {
            n.x += (mdx / mdist) * 0.45;
            n.y += (mdy / mdist) * 0.45;
          }
        }
      }

      // Draw node glow
      ctx.beginPath();
      ctx.fillStyle = warp.active ? '#6ee7b7' : 'rgba(16, 185, 129, 0.75)';
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();

      // Connect nearby nodes with silk threads
      if (!warp.active) {
        for (var j = i + 1; j < nodes.length; j++) {
          var n2 = nodes[j];
          var d = Math.hypot(n.x - n2.x, n.y - n2.y);
          if (d < 135) {
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(16, 185, 129, ' + ((1 - d / 135) * 0.24) + ')';
            ctx.lineWidth = 0.9;
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }

        // Silk strands tethered to cursor
        if (mouse.active) {
          var cmDist = Math.hypot(n.x - mouse.x, n.y - mouse.y);
          if (cmDist < 190) {
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(6, 182, 212, ' + ((1 - cmDist / 190) * 0.55) + ')';
            ctx.lineWidth = 1.2;
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.stroke();
          }
        }
      }
    }

    requestAnimationFrame(renderWebLoop);
  }
  requestAnimationFrame(renderWebLoop);

  /* ==================== VIEW & PORTAL TRANSITIONS ==================== */
  function diveIntoWorkspace(targetPanel, clickEvent, pushHistory) {
    if (state.warping) return;
    state.warping = true;

    var tx = W * 0.5;
    var ty = H * 0.5;
    if (clickEvent && clickEvent.currentTarget) {
      var rect = clickEvent.currentTarget.getBoundingClientRect();
      tx = rect.left + rect.width / 2;
      ty = rect.top + rect.height / 2;
    } else if (clickEvent && typeof clickEvent.clientX === 'number') {
      tx = clickEvent.clientX;
      ty = clickEvent.clientY;
    }

    warp.active = true;
    warp.targetX = tx;
    warp.targetY = ty;
    warp.progress = 0;

    var flash = $('warpFlash');
    flash.style.setProperty('--wx', tx + 'px');
    flash.style.setProperty('--wy', ty + 'px');
    flash.classList.add('active');

    var homeEl = $('homeView');
    homeEl.classList.remove('entering');
    homeEl.classList.add('diving');

    var start = performance.now();
    var duration = 620;

    function stepWarp(now) {
      var t = Math.min(1, (now - start) / duration);
      warp.progress = t * t;
      if (t < 1) {
        requestAnimationFrame(stepWarp);
      } else {
        warp.active = false;
        warp.progress = 0;
        flash.classList.remove('active');

        homeEl.hidden = true;
        homeEl.classList.remove('diving');

        var wsEl = $('workspaceView');
        wsEl.hidden = false;
        wsEl.classList.remove('unwarping');
        void wsEl.offsetWidth;
        wsEl.classList.add('unwarping');

        state.view = 'workspace';
        state.warping = false;
        selectPanel(targetPanel, pushHistory);
      }
    }
    requestAnimationFrame(stepWarp);
  }

  function returnToHome(pushHistory) {
    if (state.warping) return;
    state.view = 'home';

    var wsEl = $('workspaceView');
    wsEl.hidden = true;
    wsEl.classList.remove('unwarping');

    var homeEl = $('homeView');
    homeEl.hidden = false;
    homeEl.classList.remove('diving');
    homeEl.classList.remove('entering');
    void homeEl.offsetWidth;
    homeEl.classList.add('entering');

    if (pushHistory) {
      history.pushState({ view: 'home' }, '', '/');
    }
  }

  function selectPanel(name, pushHistory) {
    state.panel = name;
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
      history.pushState({ view: 'workspace', panel: name }, '', '/hub/' + name);
    }
  }

  window.addEventListener('popstate', function () {
    var path = location.pathname;
    if (path === '/' || path === '') {
      returnToHome(false);
    } else {
      $('homeView').hidden = true;
      $('workspaceView').hidden = false;
      state.view = 'workspace';
      if (path.includes('/outbound')) selectPanel('outbound', false);
      else if (path.includes('/logs')) selectPanel('logs', false);
      else selectPanel('inbound', false);
    }
  });

  /* ==================== UI HELPERS & API LOGIC ==================== */
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
      "  -d '{\"short_description\":\"Test payload from SpiderWeb Nexus\"}'";
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
    $('homeStatTotal').textContent = all.length;
    $('homeLogBadge').textContent = all.length + ' EVENTS';

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
        renderLogs();
        updateMetrics();
      }).catch(function () {});
  }

  function badge(text, cls) { return '<span class="badge ' + cls + '">' + esc(text) + '</span>'; }

  function block(label, data) {
    if (data === null || data === undefined || data === '') return '';
    if (typeof data === 'object' && Object.keys(data).length === 0) return '';
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
      head = badge(item.method || 'IN', 'b-neutral') + badge('Inbound', 'b-info') + badge(item.authMethod || 'Authenticated', 'b-ok') + '<span class="log-id">' + esc(item.id) + '</span>';
      body = block('Query Parameters', item.query) + block('Payload', item.payload);
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
      (inbound ? '<div class="log-url">' + esc(item.method || 'ANY') + ' /api/servicenow/inbound</div>' : '<div class="log-url">' + esc(item.url) + '</div>') +
      (body ? '<details data-id="' + esc(item.id) + '"' + open + '><summary>' + (inbound ? 'Query &amp; Payload' : 'Request &amp; Response') + '</summary>' + body + '</details>' : '') +
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
        short_description: "Automated incident created via SpiderWeb Nexus",
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
        selectPanel('logs', true);
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

  function setStatus(ok, uptime) {
    var pills = [$('statusPill'), $('homeStatusPill')];
    pills.forEach(function (pill) {
      if (!pill) return;
      pill.classList.toggle('ok', ok);
      pill.classList.toggle('bad', !ok);
    });
    $('statusText').textContent = ok ? 'Gateway online' : 'Gateway offline';
    $('homeStatusText').textContent = ok ? 'Nexus mesh online' : 'Mesh offline';
    if (typeof uptime === 'number') {
      $('homeStatUptime').textContent = uptime + 's';
    }
  }
  function checkHealth() {
    fetch('/health', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (d) { setStatus(true, d && d.uptimeSeconds); }, function () { setStatus(false); });
  }

  /* ==================== EVENT LISTENERS ==================== */
  document.addEventListener('click', function (e) {
    var t = e.target;
    var el;

    // Portal cards on Homepage -> Dive into SpiderWeb illusion
    if ((el = t.closest('[data-portal]'))) {
      diveIntoWorkspace(el.getAttribute('data-portal'), { currentTarget: el }, true);
      return;
    }

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
    if ((el = t.closest('[data-panel]'))) { selectPanel(el.getAttribute('data-panel'), true); return; }
    if ((el = t.closest('[data-filter]'))) {
      state.filter = el.getAttribute('data-filter');
      Array.prototype.forEach.call(document.querySelectorAll('[data-filter]'), function (b) { b.classList.toggle('active', b === el); });
      renderLogs();
      return;
    }
    if ((el = t.closest('[data-delete]'))) { deleteRecord(el.getAttribute('data-delete')); return; }
    if ((el = t.closest('[data-remove-row]'))) { el.parentElement.remove(); return; }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && document.activeElement && document.activeElement.hasAttribute('data-portal')) {
      diveIntoWorkspace(document.activeElement.getAttribute('data-portal'), { currentTarget: document.activeElement }, true);
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      if (state.view === 'workspace' && $('panel-outbound').classList.contains('active')) {
        e.preventDefault();
        sendOutbound();
      }
    }
  });

  document.addEventListener('toggle', function (e) {
    var d = e.target;
    if (d && d.matches && d.matches('details[data-id]')) state.open[d.getAttribute('data-id')] = d.open;
  }, true);

  $('returnHomeBtn').addEventListener('click', function () { returnToHome(true); });
  $('brandHomeBtn').addEventListener('click', function () { returnToHome(true); });

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

  // Route Initialization
  var initPath = location.pathname;
  if (initPath.startsWith('/hub')) {
    $('homeView').hidden = true;
    $('workspaceView').hidden = false;
    state.view = 'workspace';
    if (initPath.includes('/outbound')) selectPanel('outbound', false);
    else if (initPath.includes('/logs')) selectPanel('logs', false);
    else selectPanel('inbound', false);
  } else {
    $('homeView').hidden = false;
    $('workspaceView').hidden = true;
    state.view = 'home';
  }

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
    console.log(`NexRelay SpiderWeb Nexus running on port ${PORT}`);
});