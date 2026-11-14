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
        res.set('WWW-Authenticate', 'Basic realm="OmniBridge OAuth"');
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
        res.set('WWW-Authenticate', 'Bearer realm="OmniBridge"');
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

// ---- 100% Apple OS Glassmorphic Frontend: OmniBridge Pro · Enterprise Integration OS ----
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>OmniBridge Pro · Enterprise Integration OS</title>
<style>
:root{
  /* Apple VisionOS & macOS Sonoma Liquid Glass Design System */
  --apple-bg: #030407;
  --apple-canvas: #06080e;
  
  /* Authentic Apple Liquid Glass Materials */
  --apple-glass-ultra-thin: rgba(255, 255, 255, 0.04);
  --apple-glass-thin: rgba(255, 255, 255, 0.07);
  --apple-glass-regular: rgba(20, 24, 34, 0.62);
  --apple-glass-thick: rgba(15, 18, 27, 0.78);
  --apple-glass-hover: rgba(255, 255, 255, 0.11);
  --apple-glass-active: rgba(255, 255, 255, 0.16);

  /* Apple Specular Edge Highlights */
  --apple-border: rgba(255, 255, 255, 0.12);
  --apple-border-subtle: rgba(255, 255, 255, 0.07);
  --apple-border-bright: rgba(255, 255, 255, 0.28);
  --apple-border-glow: rgba(0, 245, 212, 0.45);

  /* Apple System Typography Colors */
  --apple-text-primary: #f5f5f7;
  --apple-text-secondary: #94949b;
  --apple-text-tertiary: #686873;
  --apple-text-link: #2997ff;

  /* Apple Vibrant System Accents */
  --accent-cyan: #00f5d4;
  --accent-cyan-soft: rgba(0, 245, 212, 0.12);
  --accent-blue: #0a84ff;
  --accent-blue-soft: rgba(10, 132, 255, 0.14);
  --accent-purple: #bf5af2;
  --accent-purple-soft: rgba(191, 90, 242, 0.14);
  --accent-mint: #30d158;
  --accent-mint-soft: rgba(48, 209, 88, 0.14);
  --accent-coral: #ff453a;
  --accent-coral-soft: rgba(255, 69, 58, 0.14);
  --accent-amber: #ff9f0a;
  --accent-amber-soft: rgba(255, 159, 10, 0.14);

  /* Apple System Blur & Shadows */
  --apple-blur: blur(40px) saturate(210%) contrast(102%);
  --apple-blur-panel: blur(48px) saturate(220%);
  --apple-shadow-sm: 0 4px 16px rgba(0, 0, 0, 0.35), inset 0 1px 1px rgba(255, 255, 255, 0.22);
  --apple-shadow-md: 0 16px 36px -8px rgba(0, 0, 0, 0.55), inset 0 1px 1px rgba(255, 255, 255, 0.28), inset 0 0 0 1px rgba(255, 255, 255, 0.05);
  --apple-shadow-lg: 0 28px 60px -12px rgba(0, 0, 0, 0.75), 0 0 40px rgba(0, 245, 212, 0.12), inset 0 1px 1px rgba(255, 255, 255, 0.38);
  --apple-shadow-card: 0 20px 48px -10px rgba(0, 0, 0, 0.65), inset 0 1px 1px rgba(255, 255, 255, 0.25), inset 0 0 0 1px rgba(255, 255, 255, 0.04);
  
  /* Font Stacks */
  --font-apple: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "SF Pro", -apple-system-subheadline, "Helvetica Neue", Helvetica, Arial, sans-serif;
  --font-mono: "SF Mono", SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, monospace;

  /* Apple Motion Curve */
  --apple-spring: cubic-bezier(0.16, 1, 0.3, 1);
  --apple-spring-bouncy: cubic-bezier(0.34, 1.56, 0.64, 1);
  --apple-ease: cubic-bezier(0.28, 0.11, 0.32, 1);

  color-scheme: dark;
}

*{box-sizing:border-box;margin:0;padding:0}
html,body{
  width:100%;min-height:100%;
  background:var(--apple-bg);
  color:var(--apple-text-primary);
  font:14px/1.55 var(--font-apple);
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
  text-rendering:optimizeLegibility;
  overflow-x:hidden;
  user-select:none;
}
button,input,select,textarea{font:inherit;color:inherit;outline:none}
[hidden]{display:none!important}

/* ==================== AMBIENT AURORA ORBS ==================== */
.ambient-scene{
  position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;
}
.aurora-orb{
  position:absolute;border-radius:50%;filter:blur(110px);opacity:0.28;
  will-change:transform;animation:floatAurora 18s ease-in-out infinite alternate;
}
.aurora-1{top:-120px;left:-100px;width:680px;height:680px;background:radial-gradient(circle, var(--accent-cyan) 0%, transparent 70%);}
.aurora-2{bottom:-150px;right:-120px;width:740px;height:740px;background:radial-gradient(circle, var(--accent-purple) 0%, transparent 70%);animation-delay:-6s;}
.aurora-3{top:35%;left:55%;width:560px;height:560px;background:radial-gradient(circle, var(--accent-blue) 0%, transparent 70%);animation-delay:-12s;opacity:0.22;}
.aurora-4{top:60%;left:10%;width:480px;height:480px;background:radial-gradient(circle, var(--accent-mint) 0%, transparent 70%);animation-delay:-9s;opacity:0.18;}

@keyframes floatAurora{
  0%{transform:translate3d(0, 0, 0) scale(1)}
  50%{transform:translate3d(60px, 40px, 0) scale(1.12)}
  100%{transform:translate3d(-40px, 70px, 0) scale(0.95)}
}

/* ==================== 60FPS SPIDER WEB CANVAS ==================== */
#webCanvas{
  position:fixed;inset:0;width:100vw;height:100vh;z-index:1;pointer-events:none;
  opacity:0.92;transition:opacity 0.5s ease;
}

/* ==================== DIMENSIONAL OPTICAL ILLUSION OVERLAY ==================== */
#illusionOverlay{
  position:fixed;inset:0;z-index:99;pointer-events:none;opacity:0;
  background:radial-gradient(circle at var(--ix, 50%) var(--iy, 50%), rgba(0, 245, 212, 0.4) 0%, rgba(191, 90, 242, 0.25) 30%, rgba(10, 132, 255, 0.15) 55%, rgba(3, 4, 7, 0.95) 85%);
  backdrop-filter:blur(0px);-webkit-backdrop-filter:blur(0px);
  transition:opacity 0.28s var(--apple-ease), backdrop-filter 0.28s var(--apple-ease);
  will-change:opacity, backdrop-filter;
}
#illusionOverlay.active{
  opacity:1;
  backdrop-filter:blur(24px) saturate(220%);-webkit-backdrop-filter:blur(24px) saturate(220%);
}
#illusionOverlay::after{
  content:'';position:absolute;inset:0;
  background:radial-gradient(circle at var(--ix, 50%) var(--iy, 50%), transparent 0%, rgba(0,0,0,0.4) 60%, rgba(0,0,0,0.85) 100%);
  animation:illusionPulse 0.45s var(--apple-spring) forwards;
}
@keyframes illusionPulse{
  0%{transform:scale(0.85);opacity:0}
  50%{opacity:1}
  100%{transform:scale(1.2);opacity:0}
}

/* ==================== APPLE OS TOP NAVIGATION STATUS BAR ==================== */
.apple-status-bar{
  position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:80;
  display:flex;align-items:center;gap:18px;padding:8px 20px;
  background:var(--apple-glass-regular);
  border:1px solid var(--apple-border);
  border-radius:9999px;
  backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  box-shadow:var(--apple-shadow-md);
  font-size:12px;font-weight:550;letter-spacing:-0.01em;
  transition:transform 0.3s var(--apple-spring), background 0.3s;
}
.apple-status-bar:hover{
  background:var(--apple-glass-hover);
  border-color:var(--apple-border-bright);
}
.apple-os-badge{
  display:flex;align-items:center;gap:8px;font-weight:700;letter-spacing:0.02em;color:#fff;
}
.apple-logo-glyph{
  width:18px;height:18px;border-radius:6px;
  background:linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
  display:grid;place-items:center;color:#03140e;box-shadow:0 0 14px rgba(0, 245, 212, 0.45);
}
.apple-divider{width:1px;height:14px;background:var(--apple-border)}
.apple-live-clock{
  font-family:var(--font-mono);font-size:11.5px;color:var(--apple-text-secondary);letter-spacing:0.02em;
}
.apple-pill-status{
  display:inline-flex;align-items:center;gap:7px;color:var(--accent-cyan);font-size:11px;font-weight:650;
  letter-spacing:0.05em;text-transform:uppercase;
}
.apple-ping-dot{
  width:7px;height:7px;border-radius:50%;background:var(--accent-cyan);
  box-shadow:0 0 10px var(--accent-cyan);animation:pingPulse 2s infinite;
}
@keyframes pingPulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:0.4}}

/* ==================== HOMEPAGE HERO (CORPORATE APPLE OS) ==================== */
.home-stage{
  position:relative;z-index:10;min-height:100vh;display:flex;flex-direction:column;
  justify-content:space-between;padding:84px 48px 32px;
  transform-origin:var(--ox, 50%) var(--oy, 50%);
  will-change:transform, opacity, filter;
  transition:filter 0.4s var(--apple-spring);
}
.home-stage.spatial-dive{
  animation:spatialDiveOut 0.48s var(--apple-ease) forwards;
  pointer-events:none;
}
.home-stage.spatial-resurface{
  animation:spatialSurfaceIn 0.52s var(--apple-spring) forwards;
}
@keyframes spatialDiveOut{
  0%{transform:perspective(1200px) scale3d(1,1,1) translateZ(0);opacity:1;filter:blur(0px)}
  100%{transform:perspective(1200px) scale3d(1.28,1.28,1.28) translateZ(80px);opacity:0;filter:blur(16px)}
}
@keyframes spatialSurfaceIn{
  0%{transform:perspective(1200px) scale3d(1.12,1.12,1.12) translateZ(50px);opacity:0;filter:blur(14px)}
  100%{transform:perspective(1200px) scale3d(1,1,1) translateZ(0);opacity:1;filter:blur(0px)}
}

.home-container{max-width:1240px;width:100%;margin:0 auto;text-align:center}

.corporate-pill{
  display:inline-flex;align-items:center;gap:10px;padding:8px 20px;border-radius:9999px;
  background:var(--apple-glass-regular);border:1px solid var(--apple-border);
  color:var(--apple-text-primary);font-size:11.5px;font-weight:650;letter-spacing:0.08em;
  text-transform:uppercase;backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  box-shadow:var(--apple-shadow-sm);margin-bottom:26px;
}
.corporate-pill .sparkle{color:var(--accent-cyan);font-size:14px}

.hero-main-title{
  font-size:clamp(40px, 6.2vw, 76px);font-weight:800;letter-spacing:-0.035em;line-height:1.05;
  margin:0 auto 20px;max-width:1000px;
  background:linear-gradient(135deg, #ffffff 0%, #f0f2f5 35%, var(--accent-cyan) 65%, var(--accent-blue) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-size:200% 100%;animation:heroSheen 10s ease-in-out infinite alternate;
}
@keyframes heroSheen{
  0%{background-position:0% 50%}
  100%{background-position:100% 50%}
}

.hero-description{
  max-width:720px;margin:0 auto 52px;font-size:17px;font-weight:420;line-height:1.65;
  letter-spacing:-0.012em;color:var(--apple-text-secondary);
}

/* ==================== 3D HOLOGRAPHIC GLASS PORTAL CARDS ==================== */
.portals-matrix{
  display:grid;grid-template-columns:repeat(3, 1fr);gap:26px;text-align:left;perspective:1000px;
}
.glass-portal{
  position:relative;background:var(--apple-glass-regular);
  border:1px solid var(--apple-border);
  border-radius:28px;padding:36px 30px;cursor:pointer;
  backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  box-shadow:var(--apple-shadow-card);
  display:flex;flex-direction:column;justify-content:space-between;min-height:280px;
  overflow:hidden;
  transition:transform 0.35s var(--apple-spring), border-color 0.3s, background 0.3s, box-shadow 0.35s;
  will-change:transform, box-shadow;
}
.glass-portal::before{
  content:'';position:absolute;inset:0;border-radius:28px;padding:1px;
  background:linear-gradient(135deg, rgba(255,255,255,0.35), rgba(0, 245, 212, 0.25), transparent 70%);
  -webkit-mask:linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none;opacity:0.5;
  transition:opacity 0.3s;
}
.glass-portal .specular-sheen{
  position:absolute;inset:0;pointer-events:none;border-radius:28px;
  background:radial-gradient(circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(255,255,255,0.14) 0%, transparent 60%);
  opacity:0;transition:opacity 0.3s;
}
.glass-portal:hover{
  transform:translate3d(0, -10px, 0) scale3d(1.025, 1.025, 1);
  border-color:var(--apple-border-bright);
  background:var(--apple-glass-hover);
  box-shadow:var(--apple-shadow-lg);
}
.glass-portal:hover::before{opacity:1}
.glass-portal:hover .specular-sheen{opacity:1}

.portal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px}
.portal-glyph{
  width:52px;height:52px;border-radius:16px;display:grid;place-items:center;
  background:var(--accent-cyan-soft);color:var(--accent-cyan);
  border:1px solid rgba(0, 245, 212, 0.35);box-shadow:0 0 20px rgba(0, 245, 212, 0.2);
  transition:transform 0.35s var(--apple-spring);
}
.glass-portal[data-portal="outbound"] .portal-glyph{
  background:var(--accent-blue-soft);color:var(--accent-blue);
  border-color:rgba(10, 132, 255, 0.35);box-shadow:0 0 20px rgba(10, 132, 255, 0.2);
}
.glass-portal[data-portal="logs"] .portal-glyph{
  background:var(--accent-amber-soft);color:var(--accent-amber);
  border-color:rgba(255, 159, 10, 0.35);box-shadow:0 0 20px rgba(255, 159, 10, 0.2);
}
.glass-portal:hover .portal-glyph{transform:scale3d(1.12, 1.12, 1) rotate(-4deg)}
.portal-glyph svg{width:24px;height:24px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

.portal-tag-pill{
  font-family:var(--font-mono);font-size:11px;font-weight:700;padding:5px 12px;border-radius:9999px;
  background:rgba(255,255,255,0.06);border:1px solid var(--apple-border);color:var(--apple-text-secondary);
}
.glass-portal h3{
  margin:0 0 10px;font-size:22px;font-weight:700;letter-spacing:-0.022em;color:var(--apple-text-primary);
}
.glass-portal p{
  margin:0 0 24px;font-size:14px;color:var(--apple-text-secondary);line-height:1.6;letter-spacing:-0.008em;
}
.portal-action{
  display:inline-flex;align-items:center;gap:9px;font-size:13.5px;font-weight:700;
  color:var(--accent-cyan);letter-spacing:0.01em;transition:transform 0.25s var(--apple-spring);
}
.glass-portal[data-portal="outbound"] .portal-action{color:var(--accent-blue)}
.glass-portal[data-portal="logs"] .portal-action{color:var(--accent-amber)}
.glass-portal:hover .portal-action{transform:translate3d(6px, 0, 0)}
.portal-action svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2.2}

/* ==================== HOMEPAGE FOOTER ==================== */
.home-meta-footer{
  max-width:1240px;width:100%;margin:0 auto;display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:16px;padding-top:28px;border-top:1px solid var(--apple-border);
  color:var(--apple-text-secondary);font-size:13px;
}
.author-credit{
  font-weight:600;letter-spacing:-0.01em;
}
.author-credit b{
  color:var(--accent-cyan);font-weight:750;letter-spacing:0.02em;
}
.system-telemetry{
  display:flex;align-items:center;gap:24px;font-family:var(--font-mono);font-size:12px;
}
.system-telemetry b{color:var(--apple-text-primary)}

/* ==================== WORKSPACE APP SHELL ==================== */
.workspace-app{
  position:relative;z-index:10;display:grid;grid-template-columns:300px minmax(0, 1fr);min-height:100vh;
  background:rgba(4, 5, 8, 0.72);
  will-change:transform, opacity;
}
.workspace-app.spatial-reveal{
  animation:workspaceRevealIn 0.54s var(--apple-spring) forwards;
}
@keyframes workspaceRevealIn{
  0%{opacity:0;transform:perspective(1200px) scale3d(0.93, 0.93, 0.93) translateZ(-60px);filter:blur(14px)}
  100%{opacity:1;transform:perspective(1200px) scale3d(1, 1, 1) translateZ(0);filter:blur(0px)}
}

/* ==================== WORKSPACE SIDEBAR ==================== */
.apple-sidebar{
  background:var(--apple-glass-regular);
  border-right:1px solid var(--apple-border);
  backdrop-filter:var(--apple-blur-panel);-webkit-backdrop-filter:var(--apple-blur-panel);
  display:flex;flex-direction:column;padding:32px 20px;
  position:sticky;top:0;height:100vh;overflow-y:auto;
}
.sidebar-brand{
  display:flex;align-items:center;gap:14px;padding:4px 8px 24px;cursor:pointer;
  transition:transform 0.25s var(--apple-spring);
}
.sidebar-brand:hover{transform:scale(1.02)}
.sidebar-logo{
  width:44px;height:44px;border-radius:14px;
  background:linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
  display:grid;place-items:center;color:#03140e;box-shadow:0 0 24px rgba(0, 245, 212, 0.35);
}
.sidebar-logo svg{width:24px;height:24px;fill:none;stroke:currentColor;stroke-width:2.2}
.sidebar-brand strong{font-size:18px;font-weight:750;letter-spacing:-0.02em;color:#fff;display:block}
.sidebar-brand span{font-size:10.5px;font-weight:800;letter-spacing:0.12em;text-transform:uppercase;color:var(--accent-cyan)}

.apple-home-return{
  display:flex;align-items:center;gap:10px;width:100%;padding:11px 16px;margin-bottom:26px;
  border:1px solid rgba(0, 245, 212, 0.35);border-radius:14px;background:var(--accent-cyan-soft);
  color:var(--accent-cyan);font-weight:700;font-size:13px;cursor:pointer;
  transition:all 0.25s var(--apple-spring);
}
.apple-home-return:hover{
  background:rgba(0, 245, 212, 0.22);transform:translate3d(-2px,0,0);box-shadow:0 0 22px rgba(0, 245, 212, 0.25);
}
.apple-home-return svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2}

.nav-section-label{
  font-size:11px;font-weight:750;letter-spacing:0.1em;text-transform:uppercase;
  padding:0 12px 10px;color:var(--apple-text-tertiary);
}
.nav-stack{display:flex;flex-direction:column;gap:6px}
.nav-tab-btn{
  position:relative;display:flex;align-items:center;gap:12px;width:100%;padding:13px 16px;
  border:1px solid transparent;border-radius:14px;
  background:transparent;color:var(--apple-text-secondary);font-weight:600;font-size:13.5px;
  text-align:left;cursor:pointer;transition:all 0.25s var(--apple-spring);
}
.nav-tab-btn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;transition:transform 0.25s}
.nav-tab-btn:hover{
  background:rgba(255,255,255,0.06);color:#fff;transform:translate3d(4px,0,0);
}
.nav-tab-btn:active{transform:scale(0.98)}
.nav-tab-btn.active{
  background:linear-gradient(90deg, rgba(0, 245, 212, 0.16), rgba(10, 132, 255, 0.08));
  color:#fff;border-color:rgba(0, 245, 212, 0.35);
  box-shadow:inset 3px 0 0 var(--accent-cyan), 0 4px 16px rgba(0,0,0,0.25);
}
.nav-tab-btn.active svg{color:var(--accent-cyan);transform:scale(1.1)}
.nav-badge{
  margin-left:auto;min-width:26px;padding:2px 8px;border-radius:9999px;
  background:var(--accent-blue-soft);color:var(--accent-blue);font-size:11px;font-weight:800;text-align:center;
}

.sidebar-footer{
  margin-top:auto;padding-top:20px;border-top:1px solid var(--apple-border);
  font-size:12px;color:var(--apple-text-secondary);
}
.sidebar-footer .status-title{
  font-size:10.5px;font-weight:750;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent-cyan);
  margin-bottom:4px;
}
.sidebar-signature{
  margin-top:12px;padding-top:12px;border-top:1px dashed var(--apple-border);
  color:#fff;font-weight:650;font-size:12px;letter-spacing:-0.01em;
}

/* ==================== WORKSPACE MAIN CONTENT ==================== */
.workspace-main{
  padding:40px 48px 56px;width:100%;max-width:1360px;display:flex;flex-direction:column;min-height:100vh;
}
.workspace-topbar{
  display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:32px;
}
.workspace-topbar h1{
  margin:0;font-size:28px;font-weight:750;letter-spacing:-0.025em;color:var(--apple-text-primary);
}
.workspace-topbar p{
  margin:6px 0 0;color:var(--apple-text-secondary);font-size:14.5px;letter-spacing:-0.01em;
}

/* Status Pill in Workspace Topbar */
.connection-pill{
  display:inline-flex;align-items:center;gap:10px;padding:9px 18px;border:1px solid var(--apple-border);
  border-radius:9999px;background:var(--apple-glass-regular);backdrop-filter:var(--apple-blur);
  font-size:12.5px;font-weight:650;letter-spacing:-0.01em;box-shadow:var(--apple-shadow-sm);
  white-space:nowrap;
}
.connection-dot{width:8px;height:8px;border-radius:50%;background:var(--apple-text-tertiary)}
.connection-pill.online .connection-dot{
  background:var(--accent-mint);box-shadow:0 0 0 5px var(--accent-mint-soft), 0 0 12px var(--accent-mint);
}
.connection-pill.offline .connection-dot{
  background:var(--accent-coral);box-shadow:0 0 0 5px var(--accent-coral-soft), 0 0 12px var(--accent-coral);
}

/* ==================== METRIC COUNTER CARDS ==================== */
.metrics-row{
  display:grid;grid-template-columns:repeat(4, 1fr);gap:18px;margin-bottom:32px;
}
.glass-metric-card{
  background:var(--apple-glass-regular);border:1px solid var(--apple-border);
  border-radius:22px;padding:22px 24px;backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  box-shadow:var(--apple-shadow-sm);transition:transform 0.3s var(--apple-spring), border-color 0.3s;
}
.glass-metric-card:hover{
  transform:translate3d(0, -4px, 0);border-color:var(--apple-border-bright);
}
.metric-header-lbl{
  font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:0.08em;
  color:var(--apple-text-tertiary);margin-bottom:8px;
}
.metric-numerical-val{
  font-size:26px;font-weight:800;font-family:var(--font-mono);letter-spacing:-0.03em;color:#fff;
}

/* ==================== PANELS & STAGGER ANIMATIONS ==================== */
.tab-content-panel{display:none}
.tab-content-panel.active{display:block}

/* Illusion Tab Entrance */
.tab-content-panel.tab-illusion-in{
  animation:tabIllusionEmerge 0.44s var(--apple-spring) forwards;
}
@keyframes tabIllusionEmerge{
  0%{opacity:0;transform:perspective(1200px) scale3d(0.95, 0.95, 0.95) translateZ(-40px);filter:blur(10px)}
  100%{opacity:1;transform:perspective(1200px) scale3d(1, 1, 1) translateZ(0);filter:blur(0px)}
}

.tab-content-panel.tab-illusion-in .stagger-item{
  opacity:0;animation:staggerCascadeIn 0.45s var(--apple-spring) forwards;
}
.tab-content-panel.tab-illusion-in .stagger-item:nth-child(1){animation-delay:0.03s}
.tab-content-panel.tab-illusion-in .stagger-item:nth-child(2){animation-delay:0.08s}
.tab-content-panel.tab-illusion-in .stagger-item:nth-child(3){animation-delay:0.13s}
.tab-content-panel.tab-illusion-in .stagger-item:nth-child(4){animation-delay:0.18s}

@keyframes staggerCascadeIn{
  0%{opacity:0;transform:translate3d(0, 18px, 0) scale3d(0.98, 0.98, 1)}
  100%{opacity:1;transform:translate3d(0, 0, 0) scale3d(1, 1, 1)}
}

/* ==================== APPLE OS CARDS & FORMS ==================== */
.apple-card{
  background:var(--apple-glass-regular);border:1px solid var(--apple-border);
  border-radius:24px;box-shadow:var(--apple-shadow-card);margin-bottom:26px;overflow:hidden;
  backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  transition:border-color 0.3s;
}
.apple-card-header{
  display:flex;align-items:center;justify-content:space-between;gap:18px;
  padding:24px 28px;border-bottom:1px solid var(--apple-border);background:rgba(255,255,255,0.02);
}
.apple-card-header h2{margin:0;font-size:18px;font-weight:700;letter-spacing:-0.015em}
.apple-card-header p{margin:4px 0 0;color:var(--apple-text-secondary);font-size:13.5px}
.apple-card-body{padding:28px}

.form-label{
  display:block;margin-bottom:8px;font-size:11.5px;font-weight:750;color:var(--apple-text-secondary);
  letter-spacing:0.06em;text-transform:uppercase;
}
.form-field{margin-bottom:22px}
.form-field:last-child{margin-bottom:0}

input,select,textarea{
  width:100%;background:rgba(8, 10, 16, 0.75);color:var(--apple-text-primary);
  border:1px solid var(--apple-border);border-radius:14px;padding:12px 18px;font:inherit;
  transition:border-color 0.25s, box-shadow 0.25s, background 0.25s;
}
textarea{font-family:var(--font-mono);font-size:13px;resize:vertical;min-height:180px;line-height:1.6}
input:focus,select:focus,textarea:focus{
  border-color:var(--accent-cyan);
  box-shadow:0 0 0 3px var(--accent-cyan-soft), 0 0 16px rgba(0, 245, 212, 0.2);
  background:rgba(12, 16, 24, 0.85);outline:none;
}
.input-glass-group{
  display:flex;align-items:stretch;border:1px solid var(--apple-border);border-radius:14px;
  background:rgba(8, 10, 16, 0.75);overflow:hidden;
  transition:border-color 0.25s, box-shadow 0.25s;
}
.input-glass-group:focus-within{
  border-color:var(--accent-cyan);box-shadow:0 0 0 3px var(--accent-cyan-soft), 0 0 16px rgba(0, 245, 212, 0.2);
}
.input-glass-group input{
  border:0;background:transparent;border-radius:0;font-family:var(--font-mono);font-size:13px;padding:12px 18px;
}
.input-glass-group input:focus{box-shadow:none;background:transparent}

.glass-icon-btn{
  display:inline-grid;place-items:center;width:48px;flex:none;border:0;
  border-left:1px solid var(--apple-border);background:transparent;color:var(--apple-text-secondary);
  cursor:pointer;transition:all 0.2s var(--apple-spring);
}
.glass-icon-btn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2}
.glass-icon-btn:hover{background:var(--accent-cyan-soft);color:var(--accent-cyan)}

/* ==================== APPLE BUTTONS & CONTROLS ==================== */
.apple-btn{
  display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:12px 24px;
  border-radius:14px;border:1px solid transparent;font-weight:700;font-size:13.5px;
  cursor:pointer;white-space:nowrap;transition:transform 0.2s var(--apple-spring), filter 0.2s, background 0.2s, box-shadow 0.2s;
}
.apple-btn svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2.2}
.apple-btn:active{transform:scale(0.97)}

.apple-btn-primary{
  background:linear-gradient(135deg, var(--accent-cyan), #00c49f);
  color:#03140e;box-shadow:0 4px 20px rgba(0, 245, 212, 0.35);font-weight:750;
}
.apple-btn-primary:hover{filter:brightness(1.08);transform:translate3d(0, -2px, 0);box-shadow:0 6px 26px rgba(0, 245, 212, 0.45)}

.apple-btn-secondary{
  background:rgba(255,255,255,0.06);color:var(--apple-text-primary);border-color:var(--apple-border);
}
.apple-btn-secondary:hover{
  background:rgba(255,255,255,0.11);border-color:var(--apple-border-bright);transform:translate3d(0, -2px, 0);
}
.apple-btn-sm{padding:8px 16px;font-size:12.5px;border-radius:12px}

.apple-btn-danger{
  background:transparent;color:var(--accent-coral);border-color:var(--apple-border);
}
.apple-btn-danger:hover{
  background:var(--accent-coral-soft);border-color:var(--accent-coral);
}

/* Apple Segmented Controls (iOS Cupertino Slider) */
.apple-segmented-track{
  display:inline-flex;padding:5px;gap:6px;background:rgba(8, 10, 16, 0.75);
  border:1px solid var(--apple-border);border-radius:9999px;margin-bottom:26px;
}
.apple-segmented-track button{
  border:0;background:transparent;padding:8px 20px;border-radius:9999px;
  font-weight:650;font-size:13px;color:var(--apple-text-secondary);cursor:pointer;
  transition:all 0.25s var(--apple-spring);
}
.apple-segmented-track button:hover{color:var(--apple-text-primary)}
.apple-segmented-track button.active{
  background:var(--apple-glass-hover);color:var(--accent-cyan);
  border:1px solid rgba(0, 245, 212, 0.35);
  box-shadow:0 4px 14px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.2);
}

/* Method selector bar in Outbound */
.outbound-url-grid{
  display:grid;grid-template-columns:140px minmax(0, 1fr) auto;gap:14px;margin-bottom:26px;
}
.outbound-url-grid select{font-weight:750}
.outbound-url-grid input{font-family:var(--font-mono);font-size:13.5px}

.header-row-pair{
  display:grid;grid-template-columns:1fr 1fr 48px;gap:12px;margin-bottom:12px;
}
.header-row-pair .glass-icon-btn{border:1px solid var(--apple-border);border-radius:14px}

.tag-field{font-family:var(--font-mono);font-weight:750;font-size:12.5px;text-align:center;cursor:default;border:1px solid;user-select:all}
.tag-cyan{color:var(--accent-cyan);background:var(--accent-cyan-soft);border-color:rgba(0, 245, 212, 0.35)}
.tag-azure{color:var(--accent-blue);background:var(--accent-blue-soft);border-color:rgba(10, 132, 255, 0.35)}
.tag-purple{color:var(--accent-purple);background:var(--accent-purple-soft);border-color:rgba(191, 90, 242, 0.35)}
.tag-amber{color:var(--accent-amber);background:var(--accent-amber-soft);border-color:rgba(255, 159, 10, 0.35)}

.auth-config-row{
  display:grid;grid-template-columns:180px 140px minmax(0, 1fr);gap:16px;align-items:end;margin-bottom:18px;
}
.auth-config-row.two-col{grid-template-columns:180px minmax(0, 1fr)}
.auth-config-row.opt-col{grid-template-columns:150px 180px minmax(0, 1fr)}
.auth-config-row .form-field{margin-bottom:0}
.form-hint{margin:14px 0 0;color:var(--apple-text-secondary);font-size:13px}
.form-hint b{color:var(--apple-text-primary)}

/* ==================== AUDIT TELEMETRY LOGS ==================== */
.logs-toolbar{
  display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:24px;
}
.flex-spacer{flex:1}

.audit-log-item{
  background:var(--apple-glass-regular);border:1px solid var(--apple-border);
  border-radius:20px;box-shadow:var(--apple-shadow-sm);margin-bottom:16px;overflow:hidden;
  backdrop-filter:var(--apple-blur);-webkit-backdrop-filter:var(--apple-blur);
  transition:border-color 0.25s, transform 0.25s;
}
.audit-log-item:hover{
  border-color:var(--apple-border-bright);
}
.log-card-header{
  display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:20px 26px;
}
.log-badges-cluster{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.log-tracking-id{font-family:var(--font-mono);font-size:13px;font-weight:750;color:#fff}
.log-timestamp{color:var(--apple-text-secondary);font-size:12.5px}
.log-endpoint-url{padding:0 26px 14px;font-family:var(--font-mono);font-size:12.5px;color:var(--apple-text-secondary);word-break:break-all}
.audit-log-item details{border-top:1px solid var(--apple-border)}
.audit-log-item summary{
  padding:14px 26px;cursor:pointer;color:var(--apple-text-secondary);font-size:13px;font-weight:600;
  transition:color 0.2s;
}
.audit-log-item summary:hover{color:#fff}
.log-body-block{padding:0 26px 22px}
.log-body-label{margin-bottom:8px;font-size:11px;font-weight:750;letter-spacing:0.08em;text-transform:uppercase;color:var(--apple-text-tertiary)}

pre{
  margin:0;padding:20px;background:rgba(6, 8, 12, 0.85);border:1px solid var(--apple-border);
  border-radius:14px;font:13px/1.6 var(--font-mono);overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-word;
}

.apple-pill-badge{
  display:inline-flex;align-items:center;padding:4px 12px;border-radius:9999px;font-size:11.5px;font-weight:750;
}
.badge-info{background:var(--accent-blue-soft);color:var(--accent-blue);border:1px solid rgba(10, 132, 255, 0.35)}
.badge-success{background:var(--accent-mint-soft);color:var(--accent-mint);border:1px solid rgba(48, 209, 88, 0.35)}
.badge-warning{background:var(--accent-amber-soft);color:var(--accent-amber);border:1px solid rgba(255, 159, 10, 0.35)}
.badge-danger{background:var(--accent-coral-soft);color:var(--accent-coral);border:1px solid rgba(255, 69, 58, 0.35)}
.badge-neutral{background:rgba(255,255,255,0.06);color:var(--apple-text-secondary);border:1px solid var(--apple-border)}

.empty-telemetry{
  display:grid;place-items:center;gap:12px;text-align:center;padding:80px 24px;
  border:1px dashed var(--apple-border);border-radius:24px;color:var(--apple-text-secondary);
  background:var(--apple-glass-regular);backdrop-filter:var(--apple-blur);
}
.empty-telemetry svg{width:38px;height:38px;color:var(--accent-cyan);fill:none;stroke:currentColor;stroke-width:1.8}
.empty-telemetry strong{color:var(--apple-text-primary);font-size:17px;font-weight:700}

/* ==================== TOASTS & MODAL DIALOGS ==================== */
.toast-container{position:fixed;right:28px;bottom:28px;display:flex;flex-direction:column;gap:12px;z-index:120}
.apple-toast{
  min-width:280px;max-width:420px;padding:16px 20px;border-radius:16px;
  background:var(--apple-glass-thick);color:var(--apple-text-primary);
  border:1px solid var(--apple-border-bright);border-left:4px solid var(--accent-cyan);
  box-shadow:var(--apple-shadow-lg);font-size:13.5px;backdrop-filter:var(--apple-blur);
  animation:toastSlideIn 0.35s var(--apple-spring);
}
@keyframes toastSlideIn{
  0%{opacity:0;transform:translate3d(0, 20px, 0) scale(0.95)}
  100%{opacity:1;transform:translate3d(0, 0, 0) scale(1)}
}
.apple-toast.success{border-left-color:var(--accent-mint)}
.apple-toast.error{border-left-color:var(--accent-coral)}

.apple-modal-overlay{
  position:fixed;inset:0;background:rgba(3, 4, 7, 0.85);display:grid;place-items:center;
  padding:24px;z-index:130;backdrop-filter:blur(20px);
}
.apple-modal-sheet{
  width:100%;max-width:460px;background:var(--apple-glass-thick);border:1px solid var(--apple-border-bright);
  border-radius:28px;padding:32px;box-shadow:var(--apple-shadow-lg);backdrop-filter:var(--apple-blur-panel);
  animation:modalSpringUp 0.38s var(--apple-spring);
}
@keyframes modalSpringUp{
  0%{opacity:0;transform:translate3d(0, 24px, 0) scale(0.94)}
  100%{opacity:1;transform:translate3d(0, 0, 0) scale(1)}
}
.apple-modal-sheet h3{margin:0 0 10px;font-size:20px;font-weight:750;letter-spacing:-0.02em}
.apple-modal-sheet p{margin:0 0 28px;color:var(--apple-text-secondary);font-size:14px;line-height:1.6}
.modal-btn-row{display:flex;justify-content:flex-end;gap:12px}

@media (max-width:980px){
  .home-stage{padding:70px 20px 24px}
  .portals-matrix{grid-template-columns:1fr}
  .workspace-app{grid-template-columns:1fr}
  .apple-sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:12px;padding:16px}
  .nav-section-label,.sidebar-footer{display:none}
  .nav-stack{flex-direction:row;flex-wrap:wrap}
  .workspace-main{padding:24px 18px 60px}
  .metrics-row,.outbound-url-grid,.auth-config-row,.auth-config-row.two-col,.auth-config-row.opt-col{grid-template-columns:1fr}
  .workspace-topbar{flex-direction:column}
}
</style>
</head>
<body>

<!-- Ambient Liquid Aurora Layers -->
<div class="ambient-scene">
  <div class="aurora-orb aurora-1"></div>
  <div class="aurora-orb aurora-2"></div>
  <div class="aurora-orb aurora-3"></div>
  <div class="aurora-orb aurora-4"></div>
</div>

<!-- SVG Icon Symbols -->
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

<!-- 60FPS Interactive Spider Web Simulation Canvas -->
<canvas id="webCanvas"></canvas>

<!-- Optical Illusion Refractive Flare Overlay -->
<div id="illusionOverlay"></div>

<!-- Top Apple OS Vision Capsule Status Bar -->
<header class="apple-status-bar">
  <div class="apple-os-badge">
    <div class="apple-logo-glyph"><svg style="width:12px;height:12px;fill:currentColor" viewBox="0 0 24 24"><use href="#i-web"/></svg></div>
    <span>OmniBridge Pro</span>
  </div>
  <div class="apple-divider"></div>
  <div class="apple-live-clock" id="systemClock">--:--:--</div>
  <div class="apple-divider"></div>
  <div class="apple-pill-status">
    <span class="apple-ping-dot"></span>
    <span id="statusBarGateway">ServiceOS 26 · Active</span>
  </div>
</header>

<!-- ==================== HOMEPAGE: CORPORATE APPLE OS DESIGN ==================== -->
<section id="homeView" class="home-stage">
  <div class="home-container">
    <div class="corporate-pill">
      <span class="sparkle">✦</span>
      <span>Enterprise ServiceNow Integration Architecture · System 26</span>
    </div>

    <h1 class="hero-main-title">OmniBridge Pro · Enterprise Integration OS</h1>
    <p class="hero-description">
      Engineered for mission-critical webhook ingestion, automated Table API dispatch, and zero-latency cryptographic audit telemetry with Apple OS spatial ergonomics.
    </p>

    <div class="portals-matrix">
      <!-- Inbound Portal -->
      <article class="glass-portal" data-portal="inbound" tabindex="0" role="button">
        <div class="specular-sheen"></div>
        <div>
          <div class="portal-header">
            <div class="portal-glyph"><svg><use href="#i-in"/></svg></div>
            <span class="portal-tag-pill">ALL HTTP METHODS</span>
          </div>
          <h3>Inbound Ingestion Gateway</h3>
          <p>High-throughput webhook listener supporting GET, POST, PUT, PATCH, and DELETE with automated cryptographic token rotation.</p>
        </div>
        <div class="portal-action">Launch Gateway <svg><use href="#i-arrow"/></svg></div>
      </article>

      <!-- Outbound Portal -->
      <article class="glass-portal" data-portal="outbound" tabindex="0" role="button">
        <div class="specular-sheen"></div>
        <div>
          <div class="portal-header">
            <div class="portal-glyph"><svg><use href="#i-out"/></svg></div>
            <span class="portal-tag-pill">REST ENGINE</span>
          </div>
          <h3>Outbound REST Dispatcher</h3>
          <p>Authenticated ServiceNow Table API client supporting OAuth 2.0 Bearer, Basic Auth, and custom headers with live schema dispatch.</p>
        </div>
        <div class="portal-action">Open Dispatcher <svg><use href="#i-arrow"/></svg></div>
      </article>

      <!-- Logs Portal -->
      <article class="glass-portal" data-portal="logs" tabindex="0" role="button">
        <div class="specular-sheen"></div>
        <div>
          <div class="portal-header">
            <div class="portal-glyph"><svg><use href="#i-list"/></svg></div>
            <span class="portal-tag-pill" id="homeEventsBadge">0 EVENTS</span>
          </div>
          <h3>Audit &amp; Telemetry Stream</h3>
          <p>Real-time packet inspection tracking roundtrip latency, HTTP status codes, and bidirectional payload telemetry across all active integrations.</p>
        </div>
        <div class="portal-action">Inspect Telemetry <svg><use href="#i-arrow"/></svg></div>
      </article>
    </div>
  </div>

  <footer class="home-meta-footer">
    <div class="author-credit">
      Engineered &amp; Designed by <b>Chadaram Veera Pavan</b>
    </div>
    <div class="system-telemetry">
      <span>TRAFFIC: <b id="statTotalTraffic">0</b></span>
      <span>UPTIME: <b id="statSystemUptime">0s</b></span>
      <span>SECURITY: <b style="color:var(--accent-mint)">TLS 1.3</b></span>
    </div>
  </footer>
</section>

<!-- ==================== WORKSPACE APP SHELL ==================== -->
<div id="workspaceView" class="workspace-app" hidden>
  <aside class="apple-sidebar">
    <div class="sidebar-brand" id="brandHomeBtn" title="Return to OmniBridge Pro Homepage">
      <div class="sidebar-logo"><svg><use href="#i-web"/></svg></div>
      <div><strong>OmniBridge Pro</strong><span>Enterprise OS</span></div>
    </div>

    <button type="button" class="apple-home-return" id="returnHomeBtn">
      <svg><use href="#i-home"/></svg>OmniBridge Overview
    </button>

    <div class="nav-section-label">Enterprise Modules</div>
    <nav class="nav-stack" aria-label="Modules Navigation">
      <button type="button" class="nav-tab-btn active" data-panel="inbound"><svg><use href="#i-in"/></svg>Inbound Webhook</button>
      <button type="button" class="nav-tab-btn" data-panel="outbound"><svg><use href="#i-out"/></svg>Outbound Client</button>
      <button type="button" class="nav-tab-btn" data-panel="logs"><svg><use href="#i-list"/></svg>Telemetry &amp; Audit<span class="nav-badge" id="sidebarLogCount">0</span></button>
    </nav>

    <div class="sidebar-footer">
      <div class="status-title">System Status</div>
      <div>Universal HTTP gateway active across all endpoints.</div>
      <div class="sidebar-signature">By Chadaram Veera Pavan</div>
    </div>
  </aside>

  <main class="workspace-main">
    <header class="workspace-topbar">
      <div><h1 id="pageTitle">Inbound Webhook Hub</h1><p id="pageSub">Receive ServiceNow payloads on a secure endpoint URL.</p></div>
      <div class="connection-pill online" id="connectionPill"><span class="connection-dot"></span><span id="connectionText">Gateway Online</span></div>
    </header>

    <div class="metrics-row">
      <div class="glass-metric-card">
        <div class="metric-header-lbl">Total Packets</div>
        <div class="metric-numerical-val" id="metricTotal">0</div>
      </div>
      <div class="glass-metric-card">
        <div class="metric-header-lbl">Success SLA</div>
        <div class="metric-numerical-val" id="metricSuccess">100%</div>
      </div>
      <div class="glass-metric-card">
        <div class="metric-header-lbl">Roundtrip Latency</div>
        <div class="metric-numerical-val" id="metricLatency">0 ms</div>
      </div>
      <div class="glass-metric-card">
        <div class="metric-header-lbl">Security Realm</div>
        <div class="metric-numerical-val" id="metricSession" style="color:var(--accent-mint)">Secured</div>
      </div>
    </div>

    <!-- Inbound Module Panel -->
    <section id="panel-inbound" class="tab-content-panel active">
      <div class="apple-card stagger-item">
        <div class="apple-card-header">
          <div><h2>Inbound Webhook Endpoint URL</h2><p>Cryptographically monitored URL endpoint accepting GET, POST, PUT, PATCH, and DELETE payloads.</p></div>
        </div>
        <div class="apple-card-body">
          <div class="form-field">
            <label class="form-label" for="inboundUrlBox">HTTPS Endpoint URL</label>
            <div class="input-glass-group">
              <input type="text" id="inboundUrlBox" readonly spellcheck="false">
              <button type="button" class="glass-icon-btn" data-copy="inboundUrlBox" data-label="Endpoint URL" title="Copy URL" aria-label="Copy endpoint URL"><svg><use href="#i-copy"/></svg></button>
            </div>
          </div>
        </div>
      </div>

      <div class="apple-card stagger-item">
        <div class="apple-card-header">
          <div><h2>Authentication &amp; Security Credentials</h2><p>Zero-trust cryptographic tokens rotated on demand. Transmitted securely via standard HTTP headers.</p></div>
          <button type="button" class="apple-btn apple-btn-secondary apple-btn-sm" id="rotateBtn"><svg><use href="#i-refresh"/></svg>Rotate Credentials</button>
        </div>
        <div class="apple-card-body">
          <div class="apple-segmented-track" role="tablist" aria-label="Authentication Scheme">
            <button type="button" class="active" data-tab-group="cred" data-tab-target="cred-bearer">Bearer Token</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-basic">Basic Auth</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-key">API Key</button>
            <button type="button" data-tab-group="cred" data-tab-target="cred-oauth">OAuth 2.0</button>
          </div>

          <!-- Bearer Token -->
          <div class="cred-sub-panel" data-panel-group="cred" id="cred-bearer">
            <div class="auth-config-row">
              <div class="form-field">
                <label class="form-label" for="bearerHeaderName">HTTP Header</label>
                <input type="text" id="bearerHeaderName" class="tag-field tag-azure" value="Authorization" readonly>
              </div>
              <div class="form-field">
                <label class="form-label" for="bearerScheme">Auth Scheme</label>
                <input type="text" id="bearerScheme" class="tag-field tag-purple" value="Bearer" readonly>
              </div>
              <div class="form-field">
                <label class="form-label" for="bearerBox">Cryptographic Token</label>
                <div class="input-glass-group">
                  <input type="password" id="bearerBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
                  <button type="button" class="glass-icon-btn" data-reveal="bearerBox" title="Toggle visibility" aria-label="Toggle token visibility"><svg><use href="#i-eye"/></svg></button>
                  <button type="button" class="glass-icon-btn" data-copy="bearerBox" data-label="Bearer token" title="Copy token" aria-label="Copy token"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <div style="margin-top:8px">
              <button type="button" class="apple-btn apple-btn-secondary apple-btn-sm" data-copy-header><svg><use href="#i-copy"/></svg>Copy Header String</button>
            </div>
            <p class="form-hint">In ServiceNow REST Message, configure an HTTP Header named <b>Authorization</b> with value <b>Bearer &lt;token&gt;</b>.</p>
          </div>

          <!-- Basic Auth -->
          <div class="cred-sub-panel" data-panel-group="cred" id="cred-basic" hidden>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
              <div class="form-field">
                <label class="form-label" for="basicUserBox">Username</label>
                <div class="input-glass-group">
                  <input type="text" id="basicUserBox" readonly spellcheck="false" placeholder="Loading…">
                  <button type="button" class="glass-icon-btn" data-copy="basicUserBox" data-label="Username" title="Copy"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="form-field">
                <label class="form-label" for="basicPassBox">Password</label>
                <div class="input-glass-group">
                  <input type="password" id="basicPassBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
                  <button type="button" class="glass-icon-btn" data-reveal="basicPassBox" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
                  <button type="button" class="glass-icon-btn" data-copy="basicPassBox" data-label="Password" title="Copy"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="form-hint">In ServiceNow, set REST Message Authentication type to <b>Basic</b>.</p>
          </div>

          <!-- API Key -->
          <div class="cred-sub-panel" data-panel-group="cred" id="cred-key" hidden>
            <div class="form-field">
              <label class="form-label" for="apiKeyBox">Secret API Key</label>
              <div class="input-glass-group">
                <input type="password" id="apiKeyBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
                <button type="button" class="glass-icon-btn" data-reveal="apiKeyBox" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
                <button type="button" class="glass-icon-btn" data-copy="apiKeyBox" data-label="API key" title="Copy"><svg><use href="#i-copy"/></svg></button>
              </div>
            </div>
            <div class="auth-config-row opt-col">
              <div class="form-field">
                <label class="form-label" for="keyViaHeader">Delivery Mode</label>
                <input type="text" id="keyViaHeader" class="tag-field tag-amber" value="HTTP Header" readonly>
              </div>
              <div class="form-field">
                <label class="form-label" for="keyHeaderName">Header Name</label>
                <input type="text" id="keyHeaderName" class="tag-field tag-cyan" value="x-sn-apikey" readonly spellcheck="false">
              </div>
              <div style="padding:12px 0;color:var(--apple-text-secondary);font-size:13px">Headers ensure URL parameters remain clean and untampered.</div>
            </div>
            <p class="form-hint">In ServiceNow, add <b>x-sn-apikey</b> as an HTTP header in your REST message configuration.</p>
          </div>

          <!-- OAuth 2.0 -->
          <div class="cred-sub-panel" data-panel-group="cred" id="cred-oauth" hidden>
            <div class="auth-config-row two-col">
              <div class="form-field">
                <label class="form-label" for="oauthGrant">OAuth Grant Type</label>
                <input type="text" id="oauthGrant" class="tag-field tag-purple" value="client_credentials" readonly>
              </div>
              <div class="form-field">
                <label class="form-label" for="oauthUrlBox">Token URL</label>
                <div class="input-glass-group">
                  <input type="text" id="oauthUrlBox" readonly spellcheck="false">
                  <button type="button" class="glass-icon-btn" data-copy="oauthUrlBox" data-label="Token URL" title="Copy"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
              <div class="form-field">
                <label class="form-label" for="oauthIdBox">Client ID</label>
                <div class="input-glass-group">
                  <input type="text" id="oauthIdBox" readonly spellcheck="false" placeholder="Loading…">
                  <button type="button" class="glass-icon-btn" data-copy="oauthIdBox" data-label="Client ID" title="Copy"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
              <div class="form-field">
                <label class="form-label" for="oauthSecretBox">Client Secret</label>
                <div class="input-glass-group">
                  <input type="password" id="oauthSecretBox" readonly autocomplete="new-password" spellcheck="false" placeholder="Loading…">
                  <button type="button" class="glass-icon-btn" data-reveal="oauthSecretBox" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
                  <button type="button" class="glass-icon-btn" data-copy="oauthSecretBox" data-label="Client secret" title="Copy"><svg><use href="#i-copy"/></svg></button>
                </div>
              </div>
            </div>
            <p class="form-hint">In ServiceNow, set Authentication type to <b>OAuth 2.0</b> targeting this Token URL.</p>
          </div>
        </div>
      </div>

      <div class="apple-card stagger-item">
        <div class="apple-card-header">
          <div><h2>Quick Test cURL</h2><p>Terminal-ready command configured for the currently selected authentication scheme.</p></div>
          <button type="button" class="apple-btn apple-btn-secondary apple-btn-sm" data-copy="curlBox" data-label="cURL command"><svg><use href="#i-copy"/></svg>Copy cURL</button>
        </div>
        <div class="apple-card-body"><pre id="curlBox">Loading credentials…</pre></div>
      </div>
    </section>

    <!-- Outbound Module Panel -->
    <section id="panel-outbound" class="tab-content-panel">
      <div class="apple-card stagger-item">
        <div class="apple-card-header">
          <div><h2>ServiceNow Request Dispatcher</h2><p>Execute authenticated REST calls directly against your PDI or enterprise instance tables.</p></div>
        </div>
        <div class="apple-card-body">
          <div class="outbound-url-grid">
            <select id="httpMethod" aria-label="HTTP Method">
              <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
            </select>
            <input type="url" id="httpUrl" placeholder="https://dev_instance.service-now.com/api/now/table/incident" spellcheck="false" aria-label="Request URL" value="https://dev_instance.service-now.com/api/now/table/incident">
            <button type="button" class="apple-btn apple-btn-primary" id="sendBtn"><svg><use href="#i-send"/></svg>Dispatch Request (⌘+Enter)</button>
          </div>

          <div class="apple-segmented-track" role="tablist" aria-label="Request Sections">
            <button type="button" class="active" data-tab-group="pm" data-tab-target="pm-auth">Authorization</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-headers">Headers</button>
            <button type="button" data-tab-group="pm" data-tab-target="pm-body">Body Payload</button>
          </div>

          <!-- Auth Tab -->
          <div class="cred-sub-panel" data-panel-group="pm" id="pm-auth">
            <div class="form-field">
              <label class="form-label" for="authType">Authentication Scheme</label>
              <select id="authType">
                <option value="basic">Basic Authentication</option>
                <option value="bearer">Bearer Token (OAuth 2.0)</option>
                <option value="apikey">API Key (Custom Header)</option>
                <option value="none">No Auth</option>
              </select>
            </div>
            <div id="basicAuthFields" style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
              <div class="form-field"><label class="form-label" for="basicUser">ServiceNow Username</label><input type="text" id="basicUser" placeholder="admin" autocomplete="off"></div>
              <div class="form-field">
                <label class="form-label" for="basicPass">ServiceNow Password</label>
                <div class="input-glass-group">
                  <input type="password" id="basicPass" placeholder="Instance password" autocomplete="new-password">
                  <button type="button" class="glass-icon-btn" data-reveal="basicPass" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
                </div>
              </div>
            </div>
            <div id="bearerAuthField" class="form-field" hidden>
              <label class="form-label" for="bearerToken">Access Token (Bearer)</label>
              <div class="input-glass-group">
                <input type="password" id="bearerToken" placeholder="Paste OAuth bearer token" autocomplete="new-password">
                <button type="button" class="glass-icon-btn" data-reveal="bearerToken" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
              </div>
            </div>
            <div id="apiKeyAuthFields" style="display:grid;grid-template-columns:1fr 1fr;gap:20px" hidden>
              <div class="form-field"><label class="form-label" for="apiKeyHeaderName">Header Key</label><input type="text" id="apiKeyHeaderName" value="x-sn-apikey" autocomplete="off"></div>
              <div class="form-field">
                <label class="form-label" for="apiKeyValue">API Key Value</label>
                <div class="input-glass-group">
                  <input type="password" id="apiKeyValue" placeholder="Paste API key" autocomplete="new-password">
                  <button type="button" class="glass-icon-btn" data-reveal="apiKeyValue" title="Show/Hide"><svg><use href="#i-eye"/></svg></button>
                </div>
              </div>
            </div>
            <p class="form-hint" id="hostHint">Requests are restricted to approved HTTPS ServiceNow hosts.</p>
          </div>

          <!-- Headers Tab -->
          <div class="cred-sub-panel" data-panel-group="pm" id="pm-headers" hidden>
            <div id="headersList"></div>
            <button type="button" class="apple-btn apple-btn-secondary apple-btn-sm" id="addHeaderBtn">+ Add Custom Header</button>
          </div>

          <!-- Body Tab -->
          <div class="cred-sub-panel" data-panel-group="pm" id="pm-body" hidden>
            <label class="form-label" for="httpBody">Raw JSON Payload</label>
            <textarea id="httpBody" rows="8" spellcheck="false">{
  "short_description": "Automated incident created via OmniBridge Pro",
  "urgency": "2",
  "impact": "2",
  "category": "software"
}</textarea>
          </div>
        </div>
      </div>
    </section>

    <!-- Logs Module Panel -->
    <section id="panel-logs" class="tab-content-panel">
      <div class="logs-toolbar stagger-item">
        <div class="apple-segmented-track" role="tablist" aria-label="Filter Logs" style="margin:0">
          <button type="button" class="active" data-filter="all">All Traffic</button>
          <button type="button" data-filter="inbound">Inbound</button>
          <button type="button" data-filter="outbound">Outbound</button>
        </div>
        <div class="flex-spacer"></div>
        <button type="button" class="apple-btn apple-btn-danger apple-btn-sm" id="clearAllBtn"><svg><use href="#i-trash"/></svg>Purge All Telemetry</button>
      </div>
      <div id="logsList" class="stagger-item"></div>
    </section>

    <footer style="margin-top:auto;padding-top:28px;border-top:1px solid var(--apple-border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;color:var(--apple-text-secondary);font-size:12.5px">
      <div>OmniBridge Pro · Enterprise Integration Suite</div>
      <div>Designed &amp; Engineered by <b style="color:var(--accent-cyan)">Chadaram Veera Pavan</b></div>
    </footer>
  </main>
</div>

<!-- Apple Liquid Glass Toast Stack -->
<div class="toast-container" id="toasts" aria-live="polite"></div>

<!-- Apple OS Confirmation Sheet Dialog -->
<div class="apple-modal-overlay" id="modal" hidden>
  <div class="apple-modal-sheet" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
    <h3 id="modalTitle"></h3>
    <p id="modalBody"></p>
    <div class="modal-btn-row">
      <button type="button" class="apple-btn apple-btn-secondary" id="modalCancel">Cancel</button>
      <button type="button" class="apple-btn apple-btn-primary" id="modalConfirm">Confirm</button>
    </div>
  </div>
</div>

<script>
(function () {
  'use strict';

  var API = '/api/servicenow';
  var MAX_RENDER_CHARS = 50000;
  var PAGES = {
    inbound: ['Inbound Ingestion Gateway', 'Cryptographically monitored URL endpoint accepting ServiceNow payloads.'],
    outbound: ['Outbound REST Dispatcher', 'Authenticated Table API execution engine supporting PDI & enterprise instances.'],
    logs: ['Audit & Telemetry Stream', 'Real-time cryptographic audit trail of inbound webhooks and outbound requests.']
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
    return isNaN(d) ? esc(iso) : esc(d.toLocaleTimeString() + ' ' + d.toLocaleDateString());
  }

  /* Live Apple OS System Clock */
  function updateClock() {
    var d = new Date();
    var s = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    var clockEl = $('systemClock');
    if (clockEl) clockEl.textContent = s;
  }
  setInterval(updateClock, 1000);
  updateClock();

  /* ==================== 60FPS SPIDER WEB PHYSICS ENGINE ==================== */
  var canvas = $('webCanvas');
  var ctx = canvas.getContext('2d');
  var W = 0, H = 0, dpr = 1;
  var mouse = { x: -9999, y: -9999, active: false };

  var webCam = {
    cx: 0, cy: 0,
    targetX: 0, targetY: 0,
    velocity: 0,
    targetVelocity: 0,
    zoom: 1,
    targetZoom: 1,
    rotation: 0
  };

  // Spider web parameters
  var SPOKE_COUNT = 20;
  var RING_COUNT = 9;
  var webNodes = []; // All intersections of spokes & concentric rings
  var shockwaves = []; // Acoustic ripples on click

  function resizeWebCanvas() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!webCam.cx) {
      webCam.cx = webCam.targetX = W * 0.5;
      webCam.cy = webCam.targetY = H * 0.46;
    }
    buildSpiderWebNodes();
  }
  window.addEventListener('resize', resizeWebCanvas);

  function buildSpiderWebNodes() {
    webNodes = [];
    var maxR = Math.max(W, H) * 0.65;
    for (var r = 1; r <= RING_COUNT; r++) {
      var radiusRatio = Math.pow(r / RING_COUNT, 1.15);
      var ringRadius = radiusRatio * maxR;
      var ring = [];
      for (var s = 0; s < SPOKE_COUNT; s++) {
        var baseAngle = (s / SPOKE_COUNT) * Math.PI * 2;
        ring.push({
          spoke: s,
          ring: r,
          baseAngle: baseAngle,
          baseR: ringRadius,
          x: 0, y: 0,
          vx: 0, vy: 0,
          elasticX: 0, elasticY: 0,
          dewdropSize: 1.2 + (r % 3 === 0 ? 1.5 : 0.6),
          isGlowing: false
        });
      }
      webNodes.push(ring);
    }
  }
  resizeWebCanvas();

  window.addEventListener('mousemove', function (e) {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
  }, { passive: true });

  window.addEventListener('mouseleave', function () {
    mouse.active = false;
  });

  // Acoustic silk shockwave impulse
  function triggerSpiderWebImpulse(x, y, zoomBoost, velocityBoost) {
    webCam.targetX = typeof x === 'number' ? x : W * 0.5;
    webCam.targetY = typeof y === 'number' ? y : H * 0.46;
    webCam.targetZoom = zoomBoost || 1.18;
    webCam.targetVelocity = velocityBoost || 24;

    shockwaves.push({
      x: x || W * 0.5,
      y: y || H * 0.46,
      radius: 0,
      maxRadius: Math.max(W, H) * 1.1,
      speed: 28,
      intensity: 1.0
    });
  }

  function settleSpiderWeb() {
    webCam.targetX = W * 0.5;
    webCam.targetY = H * 0.46;
    webCam.targetZoom = 1;
    webCam.targetVelocity = 0;
  }

  var animTime = 0;
  function renderSpiderWebLoop() {
    ctx.clearRect(0, 0, W, H);
    animTime += 0.015;

    // Camera dampening spring
    webCam.cx += (webCam.targetX - webCam.cx) * 0.08;
    webCam.cy += (webCam.targetY - webCam.cy) * 0.08;
    webCam.zoom += (webCam.targetZoom - webCam.zoom) * 0.08;
    webCam.velocity += (webCam.targetVelocity - webCam.velocity) * 0.09;
    webCam.rotation += 0.0004 + (webCam.velocity * 0.0008);

    var isHyperspace = webCam.velocity > 2;

    // Update active shockwaves
    for (var sw = shockwaves.length - 1; sw >= 0; sw--) {
      var wave = shockwaves[sw];
      wave.radius += wave.speed;
      wave.intensity *= 0.96;
      if (wave.radius > wave.maxRadius || wave.intensity < 0.02) {
        shockwaves.splice(sw, 1);
      }
    }

    // Compute nodes positions with elasticity & harmonic silk wind
    for (var r = 0; r < webNodes.length; r++) {
      var ring = webNodes[r];
      for (var s = 0; s < ring.length; s++) {
        var node = ring[s];
        var angle = node.baseAngle + webCam.rotation;
        var rDist = node.baseR * webCam.zoom;

        // Ambient silk sway (natural organic wind vibration)
        var harmonicWobble = Math.sin(animTime * 1.8 + r * 0.5 + s * 0.3) * (2.0 + r * 0.6);
        var baseX = webCam.cx + Math.cos(angle) * (rDist + harmonicWobble);
        var baseY = webCam.cy + Math.sin(angle) * (rDist + harmonicWobble);

        // Interactive mouse tension
        if (mouse.active) {
          var mdx = (baseX + node.elasticX) - mouse.x;
          var mdy = (baseY + node.elasticY) - mouse.y;
          var distToMouse = Math.hypot(mdx, mdy) || 1;
          if (distToMouse < 160) {
            var push = (1 - distToMouse / 160) * 22;
            node.vx += (mdx / distToMouse) * push * 0.12;
            node.vy += (mdy / distToMouse) * push * 0.12;
          }
        }

        // Shockwave impact
        for (var k = 0; k < shockwaves.length; k++) {
          var swave = shockwaves[k];
          var distToWaveOrigin = Math.hypot(baseX - swave.x, baseY - swave.y);
          var waveDiff = Math.abs(distToWaveOrigin - swave.radius);
          if (waveDiff < 45) {
            var waveKick = (1 - waveDiff / 45) * swave.intensity * 14;
            var pushAng = Math.atan2(baseY - swave.y, baseX - swave.x);
            node.vx += Math.cos(pushAng) * waveKick;
            node.vy += Math.sin(pushAng) * waveKick;
            node.isGlowing = true;
          }
        }

        // Spring physics restoration
        var ax = -node.elasticX * 0.08;
        var ay = -node.elasticY * 0.08;
        node.vx = (node.vx + ax) * 0.88;
        node.vy = (node.vy + ay) * 0.88;
        node.elasticX += node.vx;
        node.elasticY += node.vy;

        node.x = baseX + node.elasticX;
        node.y = baseY + node.elasticY;
      }
    }

    // DRAW SPIDER WEB SILK STRANDS
    // 1. Radial Spoke Threads
    var outerRing = webNodes[webNodes.length - 1];
    for (var sp = 0; sp < SPOKE_COUNT; sp++) {
      ctx.beginPath();
      var spokeAlpha = isHyperspace ? 0.35 : 0.15;
      ctx.strokeStyle = 'rgba(0, 245, 212, ' + spokeAlpha + ')';
      ctx.lineWidth = isHyperspace ? 1.4 : 0.85;

      ctx.moveTo(webCam.cx, webCam.cy);
      for (var rn = 0; rn < webNodes.length; rn++) {
        var n = webNodes[rn][sp];
        ctx.lineTo(n.x, n.y);
      }
      ctx.stroke();
    }

    // 2. Concentric Spiral Web Loops
    for (var rIdx = 0; rIdx < webNodes.length; rIdx++) {
      var currentRing = webNodes[rIdx];
      ctx.beginPath();
      var loopAlpha = isHyperspace ? 0.28 : (0.09 + (rIdx / webNodes.length) * 0.1);
      ctx.strokeStyle = rIdx % 2 === 0 ? 'rgba(0, 245, 212, ' + loopAlpha + ')' : 'rgba(10, 132, 255, ' + loopAlpha + ')';
      ctx.lineWidth = 0.9;

      for (var sIdx = 0; sIdx <= SPOKE_COUNT; sIdx++) {
        var nd = currentRing[sIdx % SPOKE_COUNT];
        if (sIdx === 0) ctx.moveTo(nd.x, nd.y);
        else ctx.lineTo(nd.x, nd.y);
      }
      ctx.stroke();
    }

    // 3. Shimmering Caustic Dewdrops on Web Intersections
    for (var ri = 0; ri < webNodes.length; ri++) {
      var rNodes = webNodes[ri];
      for (var si = 0; si < rNodes.length; si++) {
        var pt = rNodes[si];
        var beadRadius = pt.dewdropSize;
        if (isHyperspace) beadRadius *= 1.4;

        ctx.beginPath();
        if (pt.isGlowing || isHyperspace) {
          ctx.fillStyle = 'rgba(0, 245, 212, 0.9)';
          ctx.shadowColor = 'rgba(0, 245, 212, 0.8)';
          ctx.shadowBlur = 8;
        } else {
          ctx.fillStyle = (ri + si) % 2 === 0 ? 'rgba(255, 255, 255, 0.75)' : 'rgba(56, 189, 248, 0.75)';
          ctx.shadowBlur = 0;
        }
        ctx.arc(pt.x, pt.y, beadRadius, 0, Math.PI * 2);
        ctx.fill();
        pt.isGlowing = false;
      }
    }
    ctx.shadowBlur = 0;

    requestAnimationFrame(renderSpiderWebLoop);
  }
  requestAnimationFrame(renderSpiderWebLoop);

  /* ==================== 3D TILT EFFECT ON HOMEPAGE CARDS ==================== */
  function init3DTiltCards() {
    var cards = document.querySelectorAll('.glass-portal');
    cards.forEach(function (card) {
      card.addEventListener('mousemove', function (e) {
        var rect = card.getBoundingClientRect();
        var x = e.clientX - rect.left;
        var y = e.clientY - rect.top;
        var centerX = rect.width / 2;
        var centerY = rect.height / 2;
        var rotateX = ((y - centerY) / centerY) * -9;
        var rotateY = ((x - centerX) / centerX) * 9;

        card.style.setProperty('--mouse-x', x + 'px');
        card.style.setProperty('--mouse-y', y + 'px');
        card.style.transform = 'perspective(1000px) rotateX(' + rotateX + 'deg) rotateY(' + rotateY + 'deg) scale3d(1.025, 1.025, 1)';
      });

      card.addEventListener('mouseleave', function () {
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
      });
    });
  }
  init3DTiltCards();

  /* ==================== DIMENSIONAL OPTICAL ILLUSION TAB & VIEW TRANSITION ==================== */
  function diveIntoWorkspace(targetPanel, clickEvent, pushHistory) {
    if (state.warping) return;
    state.warping = true;

    var tx = W * 0.5;
    var ty = H * 0.45;
    if (clickEvent && clickEvent.currentTarget) {
      var rect = clickEvent.currentTarget.getBoundingClientRect();
      tx = rect.left + rect.width / 2;
      ty = rect.top + rect.height / 2;
    }

    triggerSpiderWebImpulse(tx, ty, 1.35, 28);

    var illusion = $('illusionOverlay');
    illusion.style.setProperty('--ix', tx + 'px');
    illusion.style.setProperty('--iy', ty + 'px');
    illusion.classList.add('active');

    var homeStage = $('homeView');
    homeStage.style.setProperty('--ox', tx + 'px');
    homeStage.style.setProperty('--oy', ty + 'px');
    homeStage.classList.remove('spatial-resurface');
    homeStage.classList.add('spatial-dive');

    setTimeout(function () {
      settleSpiderWeb();
      illusion.classList.remove('active');

      homeStage.hidden = true;
      homeStage.classList.remove('spatial-dive');

      var wsApp = $('workspaceView');
      wsApp.hidden = false;
      wsApp.classList.remove('spatial-reveal');
      void wsApp.offsetWidth;
      wsApp.classList.add('spatial-reveal');

      state.view = 'workspace';
      state.warping = false;
      selectPanel(targetPanel, pushHistory, true);
    }, 440);
  }

  function returnToHome(pushHistory) {
    if (state.warping) return;
    state.view = 'home';

    triggerSpiderWebImpulse(W * 0.5, H * 0.46, 1.25, 16);
    setTimeout(settleSpiderWeb, 360);

    var wsApp = $('workspaceView');
    wsApp.hidden = true;
    wsApp.classList.remove('spatial-reveal');

    var homeStage = $('homeView');
    homeStage.style.setProperty('--ox', '50%');
    homeStage.style.setProperty('--oy', '46%');
    homeStage.hidden = false;
    homeStage.classList.remove('spatial-dive');
    homeStage.classList.remove('spatial-resurface');
    void homeStage.offsetWidth;
    homeStage.classList.add('spatial-resurface');

    if (pushHistory) {
      history.pushState({ view: 'home' }, '', '/');
    }
  }

  function selectPanel(name, pushHistory, skipWebImpulse, clickEvent) {
    var changed = state.panel !== name;
    state.panel = name;

    if (changed && !skipWebImpulse) {
      var tx = W * 0.55;
      var ty = H * 0.48;
      if (clickEvent && clickEvent.currentTarget) {
        var rect = clickEvent.currentTarget.getBoundingClientRect();
        tx = rect.left + rect.width / 2;
        ty = rect.top + rect.height / 2;
      }
      triggerSpiderWebImpulse(tx, ty, 1.18, 14);
      setTimeout(settleSpiderWeb, 320);

      // Brief optical refraction flicker
      var illusion = $('illusionOverlay');
      illusion.style.setProperty('--ix', tx + 'px');
      illusion.style.setProperty('--iy', ty + 'px');
      illusion.classList.add('active');
      setTimeout(function () { illusion.classList.remove('active'); }, 180);
    }

    Array.prototype.forEach.call(document.querySelectorAll('.tab-content-panel'), function (p) {
      var isTarget = p.id === 'panel-' + name;
      p.classList.toggle('active', isTarget);
      p.classList.remove('tab-illusion-in');
      if (isTarget) {
        void p.offsetWidth;
        p.classList.add('tab-illusion-in');
      }
    });

    Array.prototype.forEach.call(document.querySelectorAll('.nav-tab-btn'), function (b) {
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
      if (path.includes('/outbound')) selectPanel('outbound', false, true);
      else if (path.includes('/logs')) selectPanel('logs', false, true);
      else selectPanel('inbound', false, true);
    }
  });

  /* ==================== TOAST & MODAL CONTROLS ==================== */
  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'apple-toast ' + (kind || 'info');
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transform = 'translate3d(0, 10px, 0)';
      setTimeout(function () { el.remove(); }, 300);
    }, 3400);
  }

  var modalResolve = null;
  function confirmDialog(opts) {
    return new Promise(function (resolve) {
      $('modalTitle').textContent = opts.title;
      $('modalBody').textContent = opts.message;
      var ok = $('modalConfirm');
      ok.textContent = opts.confirmLabel || 'Confirm';
      ok.className = 'apple-btn ' + (opts.danger ? 'apple-btn-danger' : 'apple-btn-primary');
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

  /* ==================== CREDENTIALS & CURL ENGINE ==================== */
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
    var tail = "  -H 'Content-Type: application/json' \
" +
      "  -d '{"short_description":"Automated test payload via OmniBridge Pro"}'";
    var head = "curl -X POST '" + url + "' \
";
    var out;
    if (state.credTab === 'cred-basic') {
      out = head + "  -u '" + c.username + ":" + c.password + "' \
" + tail;
    } else if (state.credTab === 'cred-key') {
      out = head + "  -H 'x-sn-apikey: " + c.apiKey + "' \
" + tail;
    } else if (state.credTab === 'cred-oauth') {
      out = "# 1) Request OAuth access token
" +
        "curl -X POST '" + $('oauthUrlBox').value + "' \
" +
        "  -d 'grant_type=client_credentials' \
" +
        "  -d 'client_id=" + c.clientId + "' \
" +
        "  -d 'client_secret=" + c.clientSecret + "'

" +
        "# 2) Call webhook endpoint with returned access_token
" +
        head + "  -H 'Authorization: Bearer <access_token>' \
" + tail;
    } else {
      out = head + "  -H 'Authorization: Bearer " + c.bearer + "' \
" + tail;
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
        toast('New cryptographic credentials issued securely. Old keys revoked.', 'success');
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
    $('statTotalTraffic').textContent = all.length;
    $('homeEventsBadge').textContent = all.length + ' EVENTS';

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

  function badge(text, cls) { return '<span class="apple-pill-badge ' + cls + '">' + esc(text) + '</span>'; }

  function block(label, data) {
    if (data === null || data === undefined || data === '') return '';
    if (typeof data === 'object' && Object.keys(data).length === 0) return '';
    var text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    var cut = false;
    if (text.length > MAX_RENDER_CHARS) { text = text.slice(0, MAX_RENDER_CHARS); cut = true; }
    return '<div class="log-body-block"><div class="log-body-label">' + esc(label) + '</div><pre>' + esc(text) + '</pre>' +
      (cut ? '<div style="color:var(--apple-text-tertiary);margin-top:6px;font-size:12px">Output truncated for performance.</div>' : '') + '</div>';
  }

  function logCard(item) {
    var inbound = item.direction === 'INBOUND';
    var delBtn = '<button type="button" class="apple-btn apple-btn-danger apple-btn-sm" data-delete="' + esc(item.id) + '">' +
      '<svg><use href="#i-trash"/></svg>Delete</button>';
    var head, body;
    if (inbound) {
      head = badge(item.method || 'IN', 'badge-neutral') + badge('Inbound', 'badge-info') + badge(item.authMethod || 'Authenticated', 'badge-success') + '<span class="log-tracking-id">' + esc(item.id) + '</span>';
      body = block('Query Parameters', item.query) + block('Payload Data', item.payload);
    } else {
      var code = item.statusCode || 0;
      var cls = code >= 200 && code < 300 ? 'badge-success' : (code >= 300 && code < 400 ? 'badge-warning' : 'badge-danger');
      head = badge(item.method, 'badge-neutral') + badge(item.status, cls) + '<span class="log-tracking-id">' + esc(item.id) + '</span>' +
        '<span class="log-timestamp">' + esc(item.durationMs) + ' ms</span>';
      body = block('Request Payload', item.requestPayload) + block('Response Body', item.responsePayload);
    }
    var open = state.open[item.id] ? ' open' : '';
    return '<article class="audit-log-item" data-card="' + esc(item.id) + '">' +
      '<div class="log-card-header"><div class="log-badges-cluster">' + head + '</div>' +
      '<div style="display:flex;align-items:center;gap:14px"><span class="log-timestamp">' + formatTime(item.timestamp) + '</span>' + delBtn + '</div></div>' +
      (inbound ? '<div class="log-endpoint-url">' + esc(item.method || 'ANY') + ' /api/servicenow/inbound</div>' : '<div class="log-endpoint-url">' + esc(item.url) + '</div>') +
      (body ? '<details data-id="' + esc(item.id) + '"' + open + '><summary>' + (inbound ? 'Inspect Payload &amp; Query' : 'Inspect Request &amp; Response') + '</summary>' + body + '</details>' : '') +
      '</article>';
  }

  function renderLogs() {
    var all = state.outbound.concat(state.inbound).sort(function (a, b) {
      return new Date(b.timestamp) - new Date(a.timestamp);
    });
    $('sidebarLogCount').textContent = all.length;
    $('clearAllBtn').disabled = all.length === 0;

    var list = all.filter(function (i) {
      return state.filter === 'all' || i.direction.toLowerCase() === state.filter;
    });
    if (!list.length) {
      $('logsList').innerHTML = '<div class="empty-telemetry"><svg><use href="#i-list"/></svg>' +
        '<strong>No telemetry records captured</strong><span>Inbound webhooks and outbound requests will stream here instantly.</span></div>';
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
      message: 'Record ' + id + ' will be permanently purged from the telemetry stream.',
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
            toast('Record ' + id + ' purged', 'success');
          }
        });
    });
  }

  function deleteAll() {
    var total = state.inbound.length + state.outbound.length;
    if (!total) { toast('No records to delete', 'info'); return; }
    confirmDialog({
      title: 'Purge all telemetry?',
      message: 'All ' + total + ' telemetry records will be permanently wiped.',
      confirmLabel: 'Purge all', danger: true
    }).then(function (yes) {
      if (!yes) return;
      return fetch(API + '/logs', { method: 'DELETE' })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
        .then(function (d) {
          state.inbound = []; state.outbound = []; state.open = {};
          resetSignature(); renderLogs(); updateMetrics();
          toast(d.deleted + ' records purged', 'success');
        });
    });
  }

  function addHeaderRow(k, v) {
    var row = document.createElement('div');
    row.className = 'header-row-pair';
    row.innerHTML = '<input type="text" class="h-key" placeholder="Header name" aria-label="Header name">' +
      '<input type="text" class="h-val" placeholder="Value" aria-label="Header value">' +
      '<button type="button" class="glass-icon-btn" data-remove-row title="Remove header" aria-label="Remove header"><svg><use href="#i-trash"/></svg></button>';
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
    if (!url) { toast('Please specify a target ServiceNow URL', 'error'); return; }

    var method = $('httpMethod').value;
    var rawBody = $('httpBody').value;
    var headers = {};
    Array.prototype.forEach.call(document.querySelectorAll('#headersList .header-row-pair'), function (row) {
      var k = row.querySelector('.h-key').value.trim();
      var v = row.querySelector('.h-val').value.trim();
      if (k) headers[k] = v;
    });

    var parsed = null;
    if (['POST', 'PUT', 'PATCH'].indexOf(method) > -1 && rawBody.trim()) {
      try { parsed = JSON.parse(rawBody); }
      catch (e) { toast('Invalid JSON syntax in request body', 'error'); return; }
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
        toast(rec.method + ' dispatched: ' + rec.status, rec.statusCode >= 200 && rec.statusCode < 300 ? 'success' : 'error');
        selectPanel('logs', true);
      } else {
        toast((r.data && r.data.message) || 'Request failed', 'error');
      }
    }).catch(function () {
      toast('Gateway unreachable', 'error');
    }).then(function () {
      state.sending = false;
      btn.disabled = false;
    });
  }

  function setStatus(ok, uptime) {
    var pill = $('connectionPill');
    if (pill) {
      pill.classList.toggle('online', ok);
      pill.classList.toggle('offline', !ok);
    }
    var text = $('connectionText');
    if (text) text.textContent = ok ? 'Gateway Online' : 'Gateway Offline';
    var barText = $('statusBarGateway');
    if (barText) barText.textContent = ok ? 'ServiceOS 26 · Active' : 'ServiceOS 26 · Offline';

    if (typeof uptime === 'number') {
      var ut = $('statSystemUptime');
      if (ut) ut.textContent = uptime + 's';
    }
  }

  function checkHealth() {
    fetch('/health', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (d) { setStatus(true, d && d.uptimeSeconds); }, function () { setStatus(false); });
  }

  /* ==================== GLOBAL EVENT LISTENERS ==================== */
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
    if ((el = t.closest('[data-panel]'))) { selectPanel(el.getAttribute('data-panel'), true, false, { currentTarget: el }); return; }
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
    console.log(`OmniBridge Pro · Enterprise Integration OS running on port ${PORT}`);
});
