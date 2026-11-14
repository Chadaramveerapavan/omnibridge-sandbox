const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;

// ---- Configuration ----
const MAX_LOGS = 200;
const BASIC_USERNAME = process.env.BASIC_USERNAME || 'nexus_admin';
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
        clientId: 'nx_' + crypto.randomBytes(6).toString('hex'),
        password: randomSecret('sn_pass_', 16),
        apiKey: randomSecret('sn_key_', 20),
        bearer: randomSecret('sn_nx_', 24),
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
        res.set('WWW-Authenticate', 'Basic realm="NexusPulse OAuth"');
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
        res.set('WWW-Authenticate', 'Bearer realm="NexusPulse"');
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

// ---- Authentic iOS 26 / visionOS Liquid Glassmorphic Frontend ----
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexusPulse · iOS Liquid Glass</title>
<style>
:root{
  --bg:#060919;
  --glass-bg:rgba(255, 255, 255, 0.065);
  --glass-bg-hover:rgba(255, 255, 255, 0.11);
  --glass-bg-deep:rgba(12, 18, 38, 0.42);
  --glass-input:rgba(255, 255, 255, 0.05);
  --glass-border:rgba(255, 255, 255, 0.22);
  --glass-border-bright:rgba(255, 255, 255, 0.48);
  --glass-blur:blur(36px) saturate(190%);
  --glass-shadow:
    0 24px 48px rgba(0, 0, 0, 0.45),
    inset 0 1px 1px rgba(255, 255, 255, 0.48),
    inset 0 -1px 2px rgba(0, 0, 0, 0.35);
  --glass-shadow-hover:
    0 32px 64px rgba(0, 0, 0, 0.55),
    inset 0 1.5px 1.5px rgba(255, 255, 255, 0.72),
    inset 0 -1px 2px rgba(0, 0, 0, 0.4);

  --text:#ffffff;
  --muted:rgba(235, 242, 255, 0.74);
  --accent:#38bdf8;
  --accent-2:#34d399;
  --ok:#34d399;
  --warn:#fbbf24;
  --coral:#fb7185;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--bg);color:var(--text);
  font:14px/1.6 -apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",Inter,sans-serif;
  -webkit-font-smoothing:antialiased;overflow-x:hidden;
}
[hidden]{display:none!important}
button{font:inherit}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid #fff;outline-offset:2px}
.icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* ==================== VIVID LIQUID MESH BLOBS ==================== */
.liquid-wallpaper{
  position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden;
  background:radial-gradient(circle at 15% 15%, #172554 0%, #090d24 55%, #040612 100%);
}
.blob{
  position:absolute;border-radius:50%;filter:blur(85px);opacity:0.78;
  will-change:transform;
}
.blob-1{
  width:560px;height:560px;top:-110px;left:-90px;
  background:radial-gradient(circle, #00f5d4 0%, #0284c7 70%);
  animation:liquidFloat1 16s ease-in-out infinite alternate;
}
.blob-2{
  width:620px;height:620px;bottom:-140px;right:-100px;
  background:radial-gradient(circle, #ec4899 0%, #7c3aed 70%);
  animation:liquidFloat2 19s ease-in-out infinite alternate;
}
.blob-3{
  width:460px;height:460px;top:36%;left:42%;
  background:radial-gradient(circle, #38bdf8 0%, #6366f1 75%);
  opacity:0.55;
  animation:liquidFloat3 14s ease-in-out infinite alternate;
}
@keyframes liquidFloat1{0%{transform:translate3d(0,0,0) scale(1)}100%{transform:translate3d(110px,80px,0) scale(1.16)}}
@keyframes liquidFloat2{0%{transform:translate3d(0,0,0) scale(1.05)}100%{transform:translate3d(-120px,-70px,0) scale(0.92)}}
@keyframes liquidFloat3{0%{transform:translate3d(-40px,20px,0) scale(0.95)}100%{transform:translate3d(70px,-60px,0) scale(1.15)}}

#webCanvas{
  position:fixed;inset:0;width:100vw;height:100vh;z-index:1;pointer-events:none;
}

/* Butter-Smooth GPU Refraction Flash */
#warpVignette{
  position:fixed;inset:0;z-index:90;pointer-events:none;opacity:0;
  background:radial-gradient(circle at var(--wx, 50%) var(--wy, 50%), rgba(255,255,255,0.32) 0%, rgba(56,189,248,0.18) 42%, rgba(6,9,25,0.8) 85%);
  transition:opacity 0.42s cubic-bezier(0.16, 1, 0.3, 1);
  will-change:opacity;
}
#warpVignette.active{opacity:1}

/* ==================== HOMEPAGE VIEW ==================== */
.home-view{
  position:relative;z-index:10;min-height:100vh;display:flex;flex-direction:column;justify-content:space-between;
  padding:32px 48px;
  transform-origin:var(--ox, 50%) var(--oy, 50%);
  will-change:transform,opacity;
}
.home-view.diving{
  animation:portalDiveOut 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
  pointer-events:none;
}
.home-view.unwarping{
  animation:portalSurfaceIn 0.52s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes portalDiveOut{
  0%{transform:scale3d(1,1,1);opacity:1}
  100%{transform:scale3d(1.22,1.22,1);opacity:0}
}
@keyframes portalSurfaceIn{
  0%{transform:scale3d(1.1,1.1,1);opacity:0}
  100%{transform:scale3d(1,1,1);opacity:1}
}

.home-nav{display:flex;align-items:center;justify-content:space-between;max-width:1280px;width:100%;margin:0 auto}
.home-brand{display:flex;align-items:center;gap:14px}
.home-logo{
  width:46px;height:46px;border-radius:15px;
  background:linear-gradient(135deg, rgba(255,255,255,0.38), rgba(255,255,255,0.08));
  border:1px solid var(--glass-border-bright);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:var(--glass-shadow);
  display:grid;place-items:center;color:#fff;
}
.home-brand strong{font-size:20px;letter-spacing:0.3px;display:block;line-height:1.1;text-shadow:0 2px 10px rgba(0,0,0,0.25)}
.home-brand span{font-size:11px;font-weight:800;letter-spacing:1.8px;text-transform:uppercase;color:#a5f3fc}

.home-hero{
  max-width:1180px;width:100%;margin:auto;text-align:center;padding:28px 0;
}
.nexus-pill{
  display:inline-flex;align-items:center;gap:10px;padding:8px 20px;border-radius:999px;
  background:var(--glass-bg);border:1px solid var(--glass-border-bright);
  color:#fff;font-size:12px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase;
  margin-bottom:22px;backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:var(--glass-shadow);
}
.nexus-pill .pulse{width:8px;height:8px;border-radius:50%;background:var(--accent-2);box-shadow:0 0 12px var(--accent-2);animation:pulseDot 2s infinite}
@keyframes pulseDot{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.6);opacity:0.45}}

.hero-title{
  margin:0 auto 16px;font-size:clamp(38px, 6vw, 68px);font-weight:800;letter-spacing:-1.5px;line-height:1.06;
  color:#ffffff;text-shadow:0 8px 32px rgba(0, 0, 0, 0.35);
}
.hero-sub{
  max-width:640px;margin:0 auto 44px;color:var(--muted);font-size:16.5px;line-height:1.65;
}

.portal-grid{
  display:grid;grid-template-columns:repeat(3, 1fr);gap:24px;text-align:left;
}
.portal-card{
  position:relative;
  background:linear-gradient(145deg, rgba(255,255,255,0.14) 0%, rgba(255,255,255,0.03) 100%);
  border:1px solid var(--glass-border);
  border-radius:28px;padding:32px 28px;cursor:pointer;
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:var(--glass-shadow);
  transition:transform 0.35s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.25s, background 0.25s, box-shadow 0.25s;
  overflow:hidden;display:flex;flex-direction:column;justify-content:space-between;min-height:245px;
}
.portal-card:hover{
  transform:translate3d(0,-8px,0) scale3d(1.02,1.02,1);
  border-color:var(--glass-border-bright);
  background:linear-gradient(145deg, rgba(255,255,255,0.22) 0%, rgba(255,255,255,0.06) 100%);
  box-shadow:var(--glass-shadow-hover);
}

.portal-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.portal-icon{
  width:50px;height:50px;border-radius:16px;display:grid;place-items:center;
  background:rgba(255,255,255,0.16);color:#fff;
  border:1px solid rgba(255,255,255,0.38);
  box-shadow:inset 0 1px 1px rgba(255,255,255,0.5), 0 8px 20px rgba(0,0,0,0.2);
  transition:transform 0.35s cubic-bezier(0.16, 1, 0.3, 1);
}
.portal-card:hover .portal-icon{transform:scale3d(1.1,1.1,1) rotate(-4deg)}
.portal-icon .icon{width:22px;height:22px}

.portal-tag{
  font-family:var(--mono);font-size:11px;font-weight:800;padding:5px 12px;border-radius:999px;
  background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.28);color:#fff;
  box-shadow:inset 0 1px 0 rgba(255,255,255,0.35);
}
.portal-card h3{margin:0 0 8px;font-size:20px;font-weight:800;color:#fff}
.portal-card p{margin:0 0 22px;font-size:13.5px;color:var(--muted);line-height:1.55}
.portal-cta{
  display:inline-flex;align-items:center;gap:8px;font-size:13.5px;font-weight:800;
  color:#fff;letter-spacing:0.2px;transition:transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.portal-card:hover .portal-cta{transform:translate3d(6px,0,0)}

.home-footer{
  max-width:1280px;width:100%;margin:0 auto;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;
  padding-top:20px;border-top:1px solid rgba(255,255,255,0.16);color:var(--muted);font-size:12.5px;
}
.creator-sig{color:#fff;font-weight:800;letter-spacing:0.3px;text-shadow:0 0 16px rgba(56,189,248,0.6)}
.home-stats{display:flex;gap:24px;font-family:var(--mono)}
.home-stats b{color:#fff}

/* ==================== WORKSPACE SHELL ==================== */
.app{
  position:relative;z-index:10;display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh;
  will-change:transform,opacity;
}
.app.entering{
  animation:workspaceEmerge 0.48s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes workspaceEmerge{
  0%{opacity:0;transform:scale3d(0.96,0.96,1)}
  100%{opacity:1;transform:scale3d(1,1,1)}
}

.sidebar{
  background:linear-gradient(180deg, rgba(255,255,255,0.11) 0%, rgba(255,255,255,0.04) 100%);
  color:var(--muted);display:flex;flex-direction:column;
  padding:28px 18px;position:sticky;top:0;height:100vh;
  border-right:1px solid var(--glass-border);
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:4px 0 32px rgba(0,0,0,0.25), inset -1px 0 0 rgba(255,255,255,0.2);
}
.brand{display:flex;align-items:center;gap:14px;padding:4px 8px 24px;cursor:pointer}
.brand-mark{
  width:42px;height:42px;border-radius:14px;
  background:linear-gradient(135deg, rgba(255,255,255,0.38), rgba(255,255,255,0.08));
  border:1px solid var(--glass-border-bright);
  box-shadow:var(--glass-shadow);
  display:grid;place-items:center;color:#fff;
}
.brand-mark .icon{width:22px;height:22px}
.brand strong{display:block;color:#fff;font-size:18px;letter-spacing:0.3px}
.brand span{font-size:11px;color:#a5f3fc;font-weight:800;text-transform:uppercase;letter-spacing:1.1px}

.home-return-btn{
  display:flex;align-items:center;gap:10px;width:100%;padding:11px 14px;margin-bottom:22px;
  border:1px solid rgba(255,255,255,0.32);border-radius:14px;
  background:linear-gradient(135deg, rgba(255,255,255,0.18), rgba(255,255,255,0.06));
  box-shadow:inset 0 1px 1px rgba(255,255,255,0.45), 0 8px 20px rgba(0,0,0,0.2);
  color:#fff;font-weight:700;font-size:13px;cursor:pointer;transition:all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.home-return-btn:hover{background:rgba(255,255,255,0.24);transform:translate3d(-3px,0,0)}

.nav{display:flex;flex-direction:column;gap:8px}
.nav-label{font-size:11px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;padding:0 12px 8px;color:rgba(255,255,255,0.55)}
.nav-item{
  display:flex;align-items:center;gap:12px;width:100%;padding:12px 15px;border:1px solid transparent;border-radius:14px;
  background:transparent;color:var(--muted);font-weight:600;text-align:left;cursor:pointer;
  transition:all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.nav-item:hover{background:rgba(255,255,255,0.08);color:#fff;transform:translate3d(4px,0,0)}
.nav-item.active{
  background:linear-gradient(135deg, rgba(255,255,255,0.22), rgba(255,255,255,0.08));
  color:#fff;border-color:rgba(255,255,255,0.4);
  box-shadow:inset 0 1px 1px rgba(255,255,255,0.5), 0 8px 24px rgba(0,0,0,0.25);
}
.count{margin-left:auto;min-width:26px;padding:2px 8px;border-radius:999px;background:rgba(255,255,255,0.2);color:#fff;font-size:11px;font-weight:800;text-align:center}

.side-foot{margin-top:auto;padding:18px 12px 0;border-top:1px solid rgba(255,255,255,0.16);font-size:12px;color:var(--muted)}
.side-foot .lbl{text-transform:uppercase;letter-spacing:1px;font-size:10.5px;color:#a5f3fc;font-weight:800;margin-bottom:4px}
.side-foot .author{margin-top:10px;padding-top:10px;border-top:1px dashed rgba(255,255,255,0.2);color:#fff;font-weight:700;font-size:11.5px}

.main{padding:34px 44px 48px;width:100%;max-width:1320px;display:flex;flex-direction:column;min-height:100vh}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:28px}
.topbar h1{margin:0;font-size:28px;font-weight:800;letter-spacing:-0.4px;color:#fff;text-shadow:0 4px 16px rgba(0,0,0,0.3)}
.topbar p{margin:5px 0 0;color:var(--muted);font-size:14px}
.status{
  display:inline-flex;align-items:center;gap:10px;padding:8px 16px;
  border:1px solid var(--glass-border-bright);border-radius:999px;
  background:var(--glass-bg);font-size:12.5px;font-weight:700;white-space:nowrap;
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  box-shadow:var(--glass-shadow);
}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted)}
.status.ok .dot{background:var(--ok);box-shadow:0 0 12px var(--ok)}
.status.bad .dot{background:var(--coral);box-shadow:0 0 12px var(--coral)}

.metrics-bar{display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:28px}
.metric-card{
  background:linear-gradient(145deg, rgba(255,255,255,0.13) 0%, rgba(255,255,255,0.04) 100%);
  border:1px solid var(--glass-border);border-radius:22px;padding:18px 22px;
  box-shadow:var(--glass-shadow);backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  transition:transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.25s;
}
.metric-card:hover{transform:translate3d(0,-3px,0);border-color:var(--glass-border-bright)}
.metric-card .label{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:6px}
.metric-card .value{font-size:22px;font-weight:800;font-family:var(--mono);color:#fff}

/* Velvet-Smooth Staggered Tab Animations */
.panel{display:none}
.panel.active{display:block}
.panel.tab-entering .stagger-item{
  opacity:0;
  animation:staggerCardIn 0.42s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
.panel.tab-entering .stagger-item:nth-child(1){animation-delay:0.02s}
.panel.tab-entering .stagger-item:nth-child(2){animation-delay:0.06s}
.panel.tab-entering .stagger-item:nth-child(3){animation-delay:0.1s}
@keyframes staggerCardIn{
  0%{opacity:0;transform:translate3d(0,14px,0) scale3d(0.985,0.985,1)}
  100%{opacity:1;transform:translate3d(0,0,0) scale3d(1,1,1)}
}

/* iOS Liquid Glass Cards */
.card{
  background:linear-gradient(145deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 100%);
  border:1px solid var(--glass-border);border-radius:26px;
  box-shadow:var(--glass-shadow);margin-bottom:24px;overflow:hidden;
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
  will-change:transform,opacity;
}
.card-head{
  display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 26px;
  border-bottom:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.04);
}
.card-head h2{margin:0;font-size:17px;font-weight:750;color:#fff}
.card-head p{margin:4px 0 0;color:var(--muted);font-size:13px}
.card-body{padding:26px}

label{display:block;margin-bottom:8px;font-size:11.5px;font-weight:800;color:var(--muted);letter-spacing:0.8px;text-transform:uppercase}
.field{margin-bottom:20px}
.field:last-child{margin-bottom:0}
input,select,textarea{
  width:100%;background:rgba(10, 15, 35, 0.35);color:#fff;
  border:1px solid rgba(255,255,255,0.22);border-radius:14px;padding:11px 16px;font:inherit;
  box-shadow:inset 0 2px 4px rgba(0,0,0,0.25);
  transition:border-color 0.2s, background 0.2s, box-shadow 0.2s;
}
textarea{font-family:var(--mono);font-size:13.5px;resize:vertical;min-height:170px}
input:focus,select:focus,textarea:focus{
  border-color:#fff;background:rgba(10, 15, 35, 0.52);
  box-shadow:0 0 0 3px rgba(255,255,255,0.2), inset 0 2px 4px rgba(0,0,0,0.25);outline:none;
}
.input-group{
  display:flex;align-items:stretch;border:1px solid rgba(255,255,255,0.22);
  border-radius:14px;background:rgba(10, 15, 35, 0.35);overflow:hidden;
  box-shadow:inset 0 2px 4px rgba(0,0,0,0.25);
}
.input-group:focus-within{border-color:#fff;box-shadow:0 0 0 3px rgba(255,255,255,0.2)}
.input-group input{border:0;background:transparent;border-radius:0;font-family:var(--mono);font-size:13.5px;padding:11px 16px;box-shadow:none}
.input-group input:focus-visible{outline:none}
.icon-btn{display:inline-grid;place-items:center;width:46px;flex:none;border:0;border-left:1px solid rgba(255,255,255,0.16);background:transparent;color:var(--muted);cursor:pointer;transition:all 0.2s}
.icon-btn:hover{background:rgba(255,255,255,0.14);color:#fff}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}

/* iOS Liquid Glass Buttons */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:11px 22px;
  border-radius:14px;border:1px solid rgba(255,255,255,0.3);font-weight:700;cursor:pointer;white-space:nowrap;
  transition:transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), filter 0.2s, background 0.2s, box-shadow 0.2s;
}
.btn-sm{padding:8px 15px;font-size:13px}
.btn-primary{
  background:linear-gradient(135deg, rgba(255,255,255,0.92), rgba(224,242,254,0.85));
  color:#061126;border-color:#fff;
  box-shadow:0 8px 24px rgba(0,0,0,0.25), inset 0 1px 1px #fff;font-weight:800;
}
.btn-primary:hover{filter:brightness(1.05);transform:translate3d(0,-2px,0);box-shadow:0 12px 28px rgba(56,189,248,0.35)}
.btn-secondary{
  background:linear-gradient(135deg, rgba(255,255,255,0.18), rgba(255,255,255,0.06));
  color:#fff;border-color:rgba(255,255,255,0.28);
  box-shadow:inset 0 1px 1px rgba(255,255,255,0.4), 0 4px 12px rgba(0,0,0,0.15);
}
.btn-secondary:hover{background:rgba(255,255,255,0.25);transform:translate3d(0,-2px,0)}
.btn-danger-ghost{background:rgba(251,113,133,0.12);color:#fecdd3;border-color:rgba(251,113,133,0.35)}
.btn-danger-ghost:hover{background:rgba(251,113,133,0.24);border-color:#fb7185}

/* iOS Segmented Control */
.seg{
  display:inline-flex;padding:5px;gap:6px;
  background:rgba(10, 15, 35, 0.38);border:1px solid rgba(255,255,255,0.18);
  border-radius:16px;margin-bottom:24px;box-shadow:inset 0 2px 4px rgba(0,0,0,0.25);
}
.seg button{border:0;background:transparent;padding:8px 18px;border-radius:12px;font-weight:700;color:var(--muted);cursor:pointer;transition:all 0.2s}
.seg button:hover{color:#fff}
.seg button.active{
  background:linear-gradient(135deg, rgba(255,255,255,0.26), rgba(255,255,255,0.1));
  color:#fff;border:1px solid rgba(255,255,255,0.42);
  box-shadow:inset 0 1px 1px rgba(255,255,255,0.5), 0 4px 12px rgba(0,0,0,0.25);
}

.url-bar{display:grid;grid-template-columns:130px minmax(0,1fr) auto;gap:12px;margin-bottom:24px}
.url-bar select{font-weight:800}
.url-bar input{font-family:var(--mono);font-size:13.5px}
.header-row{display:grid;grid-template-columns:1fr 1fr 46px;gap:12px;margin-bottom:12px}
.header-row .icon-btn{border:1px solid rgba(255,255,255,0.22);border-radius:14px}
.hint{margin:14px 0 0;color:var(--muted);font-size:13px}
.hint b{color:#fff}

.tag{font-family:var(--mono);font-weight:800;font-size:13px;text-align:center;cursor:default;border:1px solid rgba(255,255,255,0.3);user-select:all}
.tag-blue{color:#bae6fd;background:rgba(56,189,248,0.22)}
.tag-violet{color:#f5d0fe;background:rgba(217,70,239,0.22)}
.tag-amber{color:#fde68a;background:rgba(245,158,11,0.22)}
.tag-green{color:#a7f3d0;background:rgba(16,185,129,0.22)}

.auth-row{display:grid;grid-template-columns:180px 130px minmax(0,1fr);gap:14px;align-items:end;margin-bottom:16px}
.auth-row.two{grid-template-columns:180px minmax(0,1fr)}
.auth-row.opt{grid-template-columns:145px 180px minmax(0,1fr)}
.auth-row .field{margin-bottom:0}
.note-cell{padding:11px 0;color:var(--muted);font-size:13px}
.opt-title{margin:24px 0 12px;font-size:11px;font-weight:800;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted)}
.panel-actions{margin:6px 0 8px}

.toolbar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.spacer{flex:1}

.log{
  background:linear-gradient(145deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 100%);
  border:1px solid var(--glass-border);border-radius:22px;box-shadow:var(--glass-shadow);
  margin-bottom:16px;overflow:hidden;backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
}
.log-head{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;padding:18px 24px}
.log-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.log-id{font-family:var(--mono);font-size:13px;font-weight:700}
.log-meta{color:var(--muted);font-size:12.5px}
.log-actions{display:flex;align-items:center;gap:14px}
.log-url{padding:0 24px 14px;font-family:var(--mono);font-size:12.5px;color:var(--muted);word-break:break-all}
.log details{border-top:1px solid rgba(255,255,255,0.14)}
.log summary{padding:14px 24px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:600;user-select:none}
.log summary:hover{color:#fff}
.block{padding:0 24px 20px}
.block-label{margin-bottom:8px;font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--muted)}
pre{margin:0;padding:18px;background:rgba(10, 15, 35, 0.45);border:1px solid rgba(255,255,255,0.18);border-radius:14px;font:13px/1.6 var(--mono);overflow:auto;max-height:400px;white-space:pre-wrap;word-break:break-word}
.badge{display:inline-flex;align-items:center;padding:3px 11px;border-radius:999px;font-size:11.5px;font-weight:800;border:1px solid rgba(255,255,255,0.28)}
.b-info{background:rgba(56,189,248,0.22);color:#e0f2fe}
.b-ok{background:rgba(52,211,153,0.22);color:#d1fae5}
.b-warn{background:rgba(251,191,36,0.22);color:#fef3c7}
.b-err{background:rgba(251,113,133,0.22);color:#ffe4e6}
.b-neutral{background:rgba(255,255,255,0.12);color:#fff}
.empty{
  display:grid;place-items:center;gap:10px;text-align:center;padding:70px 24px;
  border:1px dashed rgba(255,255,255,0.28);border-radius:24px;color:var(--muted);
  background:var(--glass-bg);backdrop-filter:var(--glass-blur);
}
.empty .icon{width:34px;height:34px;color:#fff}
.empty strong{color:#fff;font-size:16px}

.workspace-footer{
  margin-top:auto;padding-top:24px;border-top:1px solid rgba(255,255,255,0.16);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;
  color:var(--muted);font-size:12.5px;
}

.toasts{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:10px;z-index:120}
.toast{
  min-width:270px;max-width:400px;padding:14px 18px;border-radius:16px;
  background:rgba(255,255,255,0.16);color:#fff;border:1px solid rgba(255,255,255,0.38);
  border-left:4px solid #fff;box-shadow:var(--glass-shadow);font-size:13.5px;
  backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
}
.toast.success{border-left-color:var(--ok)}
.toast.error{border-left-color:var(--coral)}

.modal{position:fixed;inset:0;background:rgba(4,6,18,0.65);display:grid;place-items:center;padding:24px;z-index:130;backdrop-filter:blur(20px)}
.dialog{
  width:100%;max-width:440px;
  background:linear-gradient(145deg, rgba(255,255,255,0.18), rgba(255,255,255,0.06));
  border:1px solid var(--glass-border-bright);border-radius:28px;padding:28px;
  box-shadow:var(--glass-shadow-hover);backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);
}
.dialog h3{margin:0 0 10px;font-size:19px;font-weight:800;color:#fff}
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
<div class="liquid-wallpaper">
  <div class="blob blob-1"></div>
  <div class="blob blob-2"></div>
  <div class="blob blob-3"></div>
</div>

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

<canvas id="webCanvas"></canvas>
<div id="warpVignette"></div>

<!-- ==================== HOMEPAGE VIEW ==================== -->
<section id="homeView" class="home-view">
  <header class="home-nav">
    <div class="home-brand">
      <div class="home-logo"><svg class="icon"><use href="#i-web"/></svg></div>
      <div>
        <strong>NexusPulse</strong>
        <span>iOS Liquid Glass</span>
      </div>
    </div>
    <div class="status" id="homeStatusPill"><span class="dot"></span><span id="homeStatusText">Syncing gateway…</span></div>
  </header>

  <div class="home-hero">
    <div class="nexus-pill"><span class="pulse"></span>Enterprise ServiceNow Integration Gateway</div>
    <h1 class="hero-title">NexusPulse · Liquid Glass</h1>
    <p class="hero-sub">High-performance enterprise workspace designed for seamless webhook ingestion, REST API execution, and live audit telemetry.</p>

    <div class="portal-grid">
      <article class="portal-card" data-portal="inbound" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-in"/></svg></div>
            <span class="portal-tag">ALL METHODS</span>
          </div>
          <h3>Inbound Webhook Hub</h3>
          <p>Capture ServiceNow GET, POST, PUT, PATCH, and DELETE payloads on a secure endpoint URL with multi-auth verification.</p>
        </div>
        <div class="portal-cta">Open Inbound Hub <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>

      <article class="portal-card" data-portal="outbound" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-out"/></svg></div>
            <span class="portal-tag">REST CLIENT</span>
          </div>
          <h3>Outbound PDI Client</h3>
          <p>Dispatch authenticated Table API requests directly to your ServiceNow instance using Basic, OAuth 2.0 Bearer, or API keys.</p>
        </div>
        <div class="portal-cta">Open Outbound Client <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>

      <article class="portal-card" data-portal="logs" tabindex="0" role="button">
        <div>
          <div class="portal-top">
            <div class="portal-icon"><svg class="icon"><use href="#i-list"/></svg></div>
            <span class="portal-tag" id="homeLogBadge">0 EVENTS</span>
          </div>
          <h3>Live Execution Logs</h3>
          <p>Inspect real-time request headers, payloads, status codes, and latency telemetry across all active integrations.</p>
        </div>
        <div class="portal-cta">Open Audit Stream <svg class="icon"><use href="#i-arrow"/></svg></div>
      </article>
    </div>
  </div>

  <footer class="home-footer">
    <div>Designed &amp; Engineered by <span class="creator-sig">Chadaram Veera Pavan</span></div>
    <div class="home-stats">
      <span>TRAFFIC: <b id="homeStatTotal">0</b></span>
      <span>UPTIME: <b id="homeStatUptime">0s</b></span>
    </div>
  </footer>
</section>

<!-- ==================== WORKSPACE VIEW ==================== -->
<div id="workspaceView" class="app" hidden>
  <aside class="sidebar">
    <div class="brand" id="brandHomeBtn" title="Return to NexusPulse Homepage">
      <div class="brand-mark"><svg class="icon"><use href="#i-web"/></svg></div>
      <div><strong>NexusPulse</strong><span>Liquid Glass</span></div>
    </div>

    <button type="button" class="home-return-btn" id="returnHomeBtn">
      <svg class="icon"><use href="#i-home"/></svg>NexusPulse Home
    </button>

    <div class="nav-label">Workspace Modules</div>
    <nav class="nav" aria-label="Primary">
      <button type="button" class="nav-item active" data-panel="inbound"><svg class="icon"><use href="#i-in"/></svg>Inbound Webhook</button>
      <button type="button" class="nav-item" data-panel="outbound"><svg class="icon"><use href="#i-out"/></svg>Outbound Client</button>
      <button type="button" class="nav-item" data-panel="logs"><svg class="icon"><use href="#i-list"/></svg>Execution Logs<span class="count" id="logCount">0</span></button>
    </nav>
    <div class="side-foot">
      <div class="lbl">Gateway Status</div>
      <div>Universal listener active (All HTTP Methods).</div>
      <div class="author">By Chadaram Veera Pavan</div>
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
      <div class="card stagger-item">
        <div class="card-head"><div><h2>Inbound Webhook Endpoint URL</h2><p>Secure endpoint URL supporting GET, POST, PUT, PATCH, and DELETE methods.</p></div></div>
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

      <div class="card stagger-item">
        <div class="card-head">
          <div><h2>Authentication Credentials</h2><p>Cryptographically secure tokens rotating on demand. Transmitted securely via HTTP headers.</p></div>
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

      <div class="card stagger-item">
        <div class="card-head">
          <div><h2>Quick Test cURL</h2><p>Ready-to-run cURL command for your selected auth method.</p></div>
          <button type="button" class="btn btn-secondary btn-sm" data-copy="curlBox" data-label="cURL command"><svg class="icon"><use href="#i-copy"/></svg>Copy</button>
        </div>
        <div class="card-body"><pre id="curlBox">Loading credentials…</pre></div>
      </div>
    </section>

    <!-- Outbound Panel -->
    <section id="panel-outbound" class="panel">
      <div class="card stagger-item">
        <div class="card-head">
          <div><h2>ServiceNow Request Builder</h2><p>Execute authenticated requests against your PDI or ServiceNow tables.</p></div>
        </div>
        <div class="card-body">
          <div class="url-bar">
            <select id="httpMethod" aria-label="HTTP method">
              <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
            </select>
            <input type="url" id="httpUrl" placeholder="https://dev_instance.service-now.com/api/now/table/incident" spellcheck="false" aria-label="Request URL" value="https://dev_instance.service-now.com/api/now/table/incident">
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
  "short_description": "Automated incident created via NexusPulse",
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
      <div class="toolbar stagger-item">
        <div class="seg" role="tablist" aria-label="Filter logs" style="margin:0">
          <button type="button" class="active" data-filter="all">All Traffic</button>
          <button type="button" class="filter-btn" data-filter="inbound">Inbound</button>
          <button type="button" class="filter-btn" data-filter="outbound">Outbound</button>
        </div>
        <div class="spacer"></div>
        <button type="button" class="btn btn-danger-ghost btn-sm" id="clearAllBtn"><svg class="icon"><use href="#i-trash"/></svg>Delete All Records</button>
      </div>
      <div id="logsList" class="stagger-item"></div>
    </section>

    <footer class="workspace-footer">
      <div>NexusPulse · Enterprise Integration Gateway</div>
      <div>Designed &amp; Engineered by <span class="creator-sig">Chadaram Veera Pavan</span></div>
    </footer>
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
    inbound: ['Inbound Webhook Hub', 'Receive ServiceNow payloads on a secure endpoint URL.'],
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

  /* ==================== 60FPS FLUID GLASS WEBCANVAS ENGINE ==================== */
  var canvas = $('webCanvas');
  var ctx = canvas.getContext('2d');
  var W = 0, H = 0, dpr = 1;
  var mouse = { x: -9999, y: -9999, active: false };

  var cam = {
    cx: 0, cy: 0,
    targetX: 0, targetY: 0,
    velocity: 0,
    targetVelocity: 0,
    zoom: 1,
    targetZoom: 1,
    rotation: 0
  };

  var nodes = [];
  var NODE_COUNT = 54;

  function resizeCanvas() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!cam.cx) {
      cam.cx = cam.targetX = W * 0.5;
      cam.cy = cam.targetY = H * 0.45;
    }
  }
  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();

  function initWebNodes() {
    nodes = [];
    for (var i = 0; i < NODE_COUNT; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        z: 0.3 + Math.random() * 0.7,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
        r: 1.5 + Math.random() * 1.8
      });
    }
  }
  initWebNodes();

  window.addEventListener('mousemove', function (e) {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
  }, { passive: true });

  window.addEventListener('mouseleave', function () {
    mouse.active = false;
  });

  function impulseWeb(tx, ty, zoomBoost, velBoost) {
    cam.targetX = typeof tx === 'number' ? tx : W * 0.5;
    cam.targetY = typeof ty === 'number' ? ty : H * 0.45;
    cam.targetZoom = zoomBoost || 1.12;
    cam.targetVelocity = velBoost || 18;
  }

  function settleWeb() {
    cam.targetX = W * 0.5;
    cam.targetY = H * 0.45;
    cam.targetZoom = 1;
    cam.targetVelocity = 0;
  }

  function renderWebLoop() {
    ctx.clearRect(0, 0, W, H);

    // Butter-smooth lerp factor (0.09) for velvet feel
    cam.cx += (cam.targetX - cam.cx) * 0.09;
    cam.cy += (cam.targetY - cam.cy) * 0.09;
    cam.zoom += (cam.targetZoom - cam.zoom) * 0.09;
    cam.velocity += (cam.targetVelocity - cam.velocity) * 0.1;
    cam.rotation += 0.0005 + (cam.velocity * 0.0009);

    var isWarping = cam.velocity > 2;

    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var prevX = n.x;
      var prevY = n.y;

      if (isWarping) {
        var dx = n.x - cam.cx;
        var dy = n.y - cam.cy;
        var dist = Math.hypot(dx, dy) || 1;
        var pull = cam.velocity * 1.15 * n.z;
        n.x += (dx / dist) * pull;
        n.y += (dy / dist) * pull;

        if (n.x < -60 || n.x > W + 60 || n.y < -60 || n.y > H + 60) {
          var spawnAng = Math.random() * Math.PI * 2;
          var spawnDist = 25 + Math.random() * 100;
          n.x = cam.cx + Math.cos(spawnAng) * spawnDist;
          n.y = cam.cy + Math.sin(spawnAng) * spawnDist;
          prevX = n.x;
          prevY = n.y;
        }
      } else {
        n.x += n.vx * n.z;
        n.y += n.vy * n.z;

        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;

        if (mouse.active) {
          var mdx = mouse.x - n.x;
          var mdy = mouse.y - n.y;
          var mdist = Math.hypot(mdx, mdy);
          if (mdist < 180 && mdist > 1) {
            n.x += (mdx / mdist) * 0.35;
            n.y += (mdy / mdist) * 0.35;
          }
        }
      }

      if (isWarping) {
        ctx.beginPath();
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
        ctx.lineWidth = 1.4 * n.z;
        ctx.moveTo(prevX, prevY);
        ctx.lineTo(n.x, n.y);
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.fillStyle = 'rgba(255, 255, 255, 0.55)';
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();

      if (!isWarping) {
        for (var j = i + 1; j < nodes.length; j++) {
          var n2 = nodes[j];
          var d = Math.hypot(n.x - n2.x, n.y - n2.y);
          if (d < 130) {
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(255, 255, 255, ' + ((1 - d / 130) * 0.14) + ')';
            ctx.lineWidth = 0.8;
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }
      }
    }

    requestAnimationFrame(renderWebLoop);
  }
  requestAnimationFrame(renderWebLoop);

  /* ==================== 60FPS VIEW & TAB TRANSITIONS ==================== */
  function diveIntoWorkspace(targetPanel, clickEvent, pushHistory) {
    if (state.warping) return;
    state.warping = true;

    var tx = W * 0.5;
    var ty = H * 0.5;
    if (clickEvent && clickEvent.currentTarget) {
      var rect = clickEvent.currentTarget.getBoundingClientRect();
      tx = rect.left + rect.width / 2;
      ty = rect.top + rect.height / 2;
    }

    impulseWeb(tx, ty, 2.2, 22);

    var vignette = $('warpVignette');
    vignette.style.setProperty('--wx', tx + 'px');
    vignette.style.setProperty('--wy', ty + 'px');
    vignette.classList.add('active');

    var homeEl = $('homeView');
    homeEl.style.setProperty('--ox', tx + 'px');
    homeEl.style.setProperty('--oy', ty + 'px');
    homeEl.classList.remove('unwarping');
    homeEl.classList.add('diving');

    setTimeout(function () {
      settleWeb();
      vignette.classList.remove('active');

      homeEl.hidden = true;
      homeEl.classList.remove('diving');

      var wsEl = $('workspaceView');
      wsEl.hidden = false;
      wsEl.classList.remove('entering');
      void wsEl.offsetWidth;
      wsEl.classList.add('entering');

      state.view = 'workspace';
      state.warping = false;
      selectPanel(targetPanel, pushHistory, true);
    }, 420);
  }

  function returnToHome(pushHistory) {
    if (state.warping) return;
    state.view = 'home';

    impulseWeb(W * 0.5, H * 0.45, 1.3, 12);
    setTimeout(settleWeb, 350);

    var wsEl = $('workspaceView');
    wsEl.hidden = true;
    wsEl.classList.remove('entering');

    var homeEl = $('homeView');
    homeEl.style.setProperty('--ox', '50%');
    homeEl.style.setProperty('--oy', '45%');
    homeEl.hidden = false;
    homeEl.classList.remove('diving');
    homeEl.classList.remove('unwarping');
    void homeEl.offsetWidth;
    homeEl.classList.add('unwarping');

    if (pushHistory) {
      history.pushState({ view: 'home' }, '', '/');
    }
  }

  function selectPanel(name, pushHistory, skipWebImpulse) {
    var changed = state.panel !== name;
    state.panel = name;

    if (changed && !skipWebImpulse) {
      impulseWeb(W * 0.55, H * 0.48, 1.15, 10);
      setTimeout(settleWeb, 300);
    }

    Array.prototype.forEach.call(document.querySelectorAll('.panel'), function (p) {
      var isTarget = p.id === 'panel-' + name;
      p.classList.toggle('active', isTarget);
      p.classList.remove('tab-entering');
      if (isTarget) {
        void p.offsetWidth;
        p.classList.add('tab-entering');
      }
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
      ok.className = 'btn ' + (opts.danger ? 'btn-danger-ghost' : 'btn-primary');
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
      "  -d '{\"short_description\":\"Test payload from NexusPulse\"}'";
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
    $('homeStatusText').textContent = ok ? 'Gateway online' : 'Gateway offline';
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

    if ((el = t.closest('[data-portal]'))) {
      diveIntoWorkspace(el.getAttribute('data-portal'), { currentTarget: el }, true);
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
    if (initPath.includes('/outbound')) selectPanel('outbound', false, true);
    else if (initPath.includes('/logs')) selectPanel('logs', false, true);
    else selectPanel('inbound', false, true);
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
    console.log(`NexusPulse iOS Liquid Glass running on port ${PORT}`);
});