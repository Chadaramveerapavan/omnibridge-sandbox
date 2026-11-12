
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));

// Persistent execution history stored beside server.js
const DATABASE_FILE = path.join(__dirname, 'database.json');

function loadDatabase() {
    try {
        if (!fs.existsSync(DATABASE_FILE)) {
            fs.writeFileSync(DATABASE_FILE, JSON.stringify({ inbound: [], outbound: [] }, null, 2));
        }

        const data = JSON.parse(fs.readFileSync(DATABASE_FILE, 'utf8'));
        return {
            inbound: Array.isArray(data.inbound) ? data.inbound : [],
            outbound: Array.isArray(data.outbound) ? data.outbound : []
        };
    } catch (error) {
        console.error('[Database] Could not load database.json:', error.message);
        return { inbound: [], outbound: [] };
    }
}

let database = loadDatabase();
let inboundLogs = database.inbound;
let outboundLogs = database.outbound;

function saveDatabase() {
    const tempFile = DATABASE_FILE + '.tmp';
    try {
        fs.writeFileSync(tempFile, JSON.stringify({
            inbound: inboundLogs,
            outbound: outboundLogs
        }, null, 2));
        fs.renameSync(tempFile, DATABASE_FILE);
    } catch (error) {
        console.error('[Database] Could not save execution history:', error.message);
        try {
            if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
        } catch (_) {}
        throw error;
    }
}

// 1. ServiceNow Inbound REST Endpoint
app.post('/api/v1/servicenow/inbound', (req, res) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || (!authHeader.startsWith('Bearer sn_nex_') && !authHeader.startsWith('Bearer sn_dev_'))) {
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Authentication failed: The provided Bearer token in the Authorization header is invalid or missing.' 
        });
    }

    const syncId = "SN-INB-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();

    const inboundEntry = {
        id: syncId,
        direction: 'INBOUND',
        timestamp,
        headers: {
            'content-type': req.headers['content-type'],
            'authorization': 'Bearer ********'
        },
        payload: req.body
    };

    inboundLogs.unshift(inboundEntry);
    saveDatabase();
    console.log(`[ServiceNow Inbound] ID: ${syncId}`);

    res.status(200).json({
        status: 'Success',
        message: 'Inbound ServiceNow payload successfully ingested by NexRelay.',
        record: inboundEntry
    });
});

// 2. Postman-Style Outbound HTTP Proxy
app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const { method, url, authType, basicUser, basicPass, bearerToken, headers, body } = req.body;

    if (!url || !method) {
        return res.status(400).json({ 
            status: 'Error', 
            message: 'Validation Error: Both HTTP Method and Target Endpoint URL are required to execute the request.' 
        });
    }

    let targetUrl;
    try {
        targetUrl = new URL(url);
    } catch (_) {
        return res.status(400).json({ status: 'Error', message: 'Please provide a valid target URL.' });
    }

    if (targetUrl.protocol !== 'https:' || !targetUrl.hostname.endsWith('.service-now.com')) {
        return res.status(400).json({
            status: 'Error',
            message: 'For security, NexRelay only accepts HTTPS URLs hosted on *.service-now.com.'
        });
    }

    const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
    if (!allowedMethods.includes(String(method).toUpperCase())) {
        return res.status(400).json({ status: 'Error', message: 'Unsupported HTTP method.' });
    }

    const syncId = "SN-OUT-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();
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
    }

    const fetchOptions = {
        method: method.toUpperCase(),
        headers: requestHeaders
    };

    if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase()) && body) {
        fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    let responseStatus = 200;
    let statusText = 'OK';
    let responseData = null;
    let durationMs = 0;
    let diagnosticError = null;

    try {
        const response = await fetch(targetUrl.toString(), { ...fetchOptions, signal: AbortSignal.timeout(20000) });
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
        statusText = 'Network DNS or TLS Failure';
        diagnosticError = error.message;
        responseData = {
            error: error.message,
            diagnosticAdvice: 'Verify that your ServiceNow Personal Developer Instance (PDI) is online and reachable. Check firewall rules, VPN configurations, and ensure the URL prefix matches standard instance routing.'
        };
    }

    const outboundEntry = {
        id: syncId,
        direction: 'OUTBOUND',
        method: method.toUpperCase(),
        url,
        status: `${responseStatus} ${statusText}`,
        statusCode: responseStatus,
        durationMs,
        timestamp,
        diagnosticError,
        requestPayload: fetchOptions.body ? (() => {
            try { return JSON.parse(fetchOptions.body); }
            catch (_) { return fetchOptions.body; }
        })() : null,
        responsePayload: responseData
    };

    outboundLogs.unshift(outboundEntry);
    saveDatabase();
    console.log(`[ServiceNow Outbound] ${method.toUpperCase()} ${url} -> ${responseStatus} (${durationMs}ms)`);

    res.status(200).json({
        status: responseStatus >= 200 && responseStatus < 300 ? 'Completed' : 'Failed',
        record: outboundEntry
    });
});

// Read saved execution history
app.get('/api/v1/servicenow/logs', (req, res) => {
    res.json({
        inbound: inboundLogs,
        outbound: outboundLogs
    });
});

// Delete one NexRelay history entry. This does NOT delete the record in ServiceNow.
app.delete('/api/v1/servicenow/logs/:direction/:id', (req, res) => {
    const direction = req.params.direction.toLowerCase();
    const id = req.params.id;

    let selectedLogs;
    if (direction === 'inbound') selectedLogs = inboundLogs;
    else if (direction === 'outbound') selectedLogs = outboundLogs;
    else return res.status(400).json({ status: 'Error', message: 'Invalid log direction.' });

    const index = selectedLogs.findIndex(item => item.id === id);
    if (index === -1) {
        return res.status(404).json({ status: 'Error', message: 'History entry not found.' });
    }

    selectedLogs.splice(index, 1);
    saveDatabase();

    res.json({ status: 'Success', message: 'NexRelay history entry deleted.' });
});

// 3. Masterpiece Frontend (Heavy Background Aurora + Constellation Mesh + Clean Non-Overlapping Icon Controls)
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexRelay | Masterpiece ServiceNow Integration Hub</title>
    <style>
        :root {
            --bg: #030409;
            --surface: #0a0e1a;
            --surface-card: rgba(16, 22, 40, 0.82);
            --surface-elevated: #18223c;
            --border: rgba(99, 102, 241, 0.22);
            --border-hover: rgba(99, 102, 241, 0.5);
            --indigo: #6366f1;
            --indigo-glow: rgba(99, 102, 241, 0.35);
            --cyan: #38bdf8;
            --cyan-glow: rgba(56, 189, 248, 0.3);
            --emerald: #10b981;
            --danger: #f43f5e;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * { box-sizing: border-box; cursor: none !important; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 36px 24px;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        /* Heavy Multi-Layered Background Animations */
        #bgCanvas {
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            pointer-events: none;
            z-index: -3;
        }

        .aurora-layer {
            position: fixed;
            inset: -50%;
            width: 200%;
            height: 200%;
            pointer-events: none;
            z-index: -2;
            background: 
                radial-gradient(circle at 30% 30%, rgba(99, 102, 241, 0.16) 0%, transparent 35%),
                radial-gradient(circle at 70% 65%, rgba(56, 189, 248, 0.14) 0%, transparent 35%),
                radial-gradient(circle at 45% 80%, rgba(16, 185, 129, 0.09) 0%, transparent 30%);
            animation: auroraDrift 18s ease-in-out infinite alternate;
        }

        .cyber-grid {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: -1;
            background-image: 
                linear-gradient(to right, rgba(99, 102, 241, 0.04) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(99, 102, 241, 0.04) 1px, transparent 1px);
            background-size: 48px 48px;
            mask-image: radial-gradient(ellipse at center, black 40%, transparent 85%);
            -webkit-mask-image: radial-gradient(ellipse at center, black 40%, transparent 85%);
            animation: gridPulse 8s ease-in-out infinite alternate;
        }

        @keyframes auroraDrift {
            0% { transform: translate(0, 0) rotate(0deg) scale(1); }
            50% { transform: translate(-4%, 3%) rotate(4deg) scale(1.05); }
            100% { transform: translate(4%, -4%) rotate(-4deg) scale(1.08); }
        }

        @keyframes gridPulse {
            0% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        /* Custom Glowing Cursor */
        .cursor-dot {
            position: fixed; top: 0; left: 0; width: 8px; height: 8px;
            background: var(--cyan); border-radius: 50%;
            pointer-events: none; z-index: 99999;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 14px var(--cyan);
            transition: transform 0.08s ease;
        }
        .cursor-outline {
            position: fixed; top: 0; left: 0; width: 40px; height: 40px;
            border: 1px solid rgba(99, 102, 241, 0.55); border-radius: 50%;
            pointer-events: none; z-index: 99998;
            transform: translate(-50%, -50%);
            transition: width 0.25s ease, height 0.25s ease, border-color 0.25s ease, background 0.25s ease;
            background: rgba(99, 102, 241, 0.04);
        }
        body.hovering .cursor-outline {
            width: 56px; height: 56px;
            border-color: var(--cyan);
            background: rgba(56, 189, 248, 0.12);
        }

        .container { max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }

        @keyframes heavyFadeIn {
            from { opacity: 0; transform: translateY(20px) scale(0.99); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .animate-in { animation: heavyFadeIn 0.55s cubic-bezier(0.16, 1, 0.3, 1) forwards; }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .brand { display: flex; align-items: center; gap: 14px; }
        .brand-icon {
            width: 48px; height: 48px; border-radius: 14px;
            display: grid; place-items: center;
            background: linear-gradient(135deg, #6366f1, #0ea5e9);
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.25);
            font-size: 22px; font-weight: 800; color: white;
        }
        .brand h1 { font-size: 22px; margin: 0; letter-spacing: -0.6px; font-weight: 750; }
        .brand p { margin: 4px 0 0; color: var(--text-muted); font-size: 12px; letter-spacing: 0.3px; }

        .header-status {
            display: flex; align-items: center; gap: 10px;
            padding: 8px 14px; border: 1px solid var(--border);
            border-radius: 999px; background: rgba(16, 22, 40, 0.65);
            font-size: 12px; color: #cbd5e1;
        }
        .status-dot {
            width: 7px; height: 7px; border-radius: 50%;
            background: var(--emerald); box-shadow: 0 0 10px var(--emerald);
            animation: statusPulse 2s infinite;
        }
        @keyframes statusPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.45; }
        }

        .nav-bar {
            display: flex; gap: 8px; padding: 6px;
            border: 1px solid var(--border); border-radius: 14px;
            background: rgba(10, 14, 26, 0.75);
            margin-bottom: 24px; width: fit-content; max-width: 100%;
            flex-wrap: wrap;
        }
        .nav-btn {
            border: 0; background: transparent; color: var(--text-muted);
            padding: 11px 18px; border-radius: 9px; font-size: 13px;
            font-weight: 650; transition: all 0.25s ease;
        }
        .nav-btn:hover { color: white; background: rgba(99, 102, 241, 0.1); }
        .nav-btn.active {
            color: white; background: linear-gradient(135deg, rgba(99, 102, 241, 0.25), rgba(56, 189, 248, 0.12));
            box-shadow: inset 0 0 0 1px rgba(99, 102, 241, 0.28);
        }

        .workspace-panel { display: none; }
        .workspace-panel.active { display: block; animation: heavyFadeIn 0.45s ease forwards; }

        .panel-heading { margin-bottom: 22px; }
        .panel-heading h2 { margin: 0 0 7px; font-size: 21px; letter-spacing: -0.5px; }
        .panel-heading p { margin: 0; color: var(--text-muted); font-size: 13px; line-height: 1.6; }

        .workspace-grid {
            display: grid; grid-template-columns: 1.1fr 0.9fr;
            gap: 22px; align-items: start;
        }
        .card {
            background: var(--surface-card); border: 1px solid var(--border);
            border-radius: 16px; padding: 22px;
            box-shadow: 0 18px 45px rgba(0, 0, 0, 0.18);
            backdrop-filter: blur(18px);
        }
        .card h3 { margin: 0 0 18px; font-size: 15px; font-weight: 700; }
        .field { margin-bottom: 16px; }
        .field label, label {
            display: block; color: #cbd5e1; font-size: 11px;
            font-weight: 700; letter-spacing: 0.7px; text-transform: uppercase;
            margin-bottom: 8px;
        }
        input, select, textarea {
            width: 100%; border: 1px solid rgba(99, 102, 241, 0.24);
            background: rgba(3, 4, 9, 0.72); color: white;
            padding: 12px 13px; border-radius: 9px; outline: none;
            font-family: inherit; font-size: 13px; transition: border 0.2s ease, box-shadow 0.2s ease;
        }
        input:focus, select:focus, textarea:focus {
            border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.1);
        }
        input::placeholder, textarea::placeholder { color: #64748b; }
        select option { background: #0a0e1a; color: white; }
        textarea { min-height: 190px; resize: vertical; font-family: "SFMono-Regular", Consolas, monospace; line-height: 1.5; }
        input:disabled, textarea:disabled { opacity: 0.4; cursor: not-allowed !important; }

        .btn {
            border: 0; border-radius: 9px; padding: 12px 18px;
            font-weight: 750; font-size: 12px; letter-spacing: 0.4px;
            color: white; background: linear-gradient(135deg, #6366f1, #2563eb);
            box-shadow: 0 8px 22px rgba(79, 70, 229, 0.25);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 12px 28px rgba(79, 70, 229, 0.35); }
        .btn:disabled { opacity: 0.55; transform: none; }
        .btn-secondary {
            background: rgba(99, 102, 241, 0.1); border: 1px solid var(--border);
            box-shadow: none; color: #c7d2fe;
        }
        .btn-secondary:hover { background: rgba(99, 102, 241, 0.2); box-shadow: none; }
        .icon-btn {
            width: 34px; height: 34px; border-radius: 8px; border: 1px solid var(--border);
            background: rgba(244, 63, 94, 0.08); color: #fda4af; font-size: 18px;
            display: grid; place-items: center; flex-shrink: 0;
        }

        .url-row { display: flex; gap: 8px; }
        .url-row select { width: 105px; flex-shrink: 0; font-weight: 800; color: var(--cyan); }
        .url-row input { flex: 1; min-width: 0; }
        .header-row { display: flex; gap: 8px; margin-bottom: 8px; }
        .header-row input { flex: 1; min-width: 0; }
        .auth-fields { display: none; margin-top: 12px; padding: 14px; border: 1px dashed var(--border); border-radius: 10px; }
        .pm-tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
        .pm-tab {
            border: 0; background: transparent; color: var(--text-muted);
            padding: 10px 12px; font-size: 12px; font-weight: 700;
            border-bottom: 2px solid transparent;
        }
        .pm-tab.active { color: var(--cyan); border-bottom-color: var(--cyan); }
        .pm-panel { display: none; }
        .pm-panel.active { display: block; }
        .helper-text { color: var(--text-muted); font-size: 11px; line-height: 1.5; margin-top: 7px; }
        .endpoint-box {
            border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 10px;
            background: rgba(56, 189, 248, 0.05); padding: 13px;
            font-family: monospace; font-size: 11px; color: #7dd3fc;
            word-break: break-all; line-height: 1.6;
        }

        .logs-container { display: grid; gap: 14px; }
        .log-card {
            background: rgba(10, 14, 26, 0.8); border: 1px solid var(--border);
            border-radius: 12px; padding: 17px; overflow: hidden;
        }
        .log-meta {
            display: flex; justify-content: space-between; align-items: center;
            gap: 12px; flex-wrap: wrap; margin-bottom: 12px;
        }
        .badge {
            display: inline-flex; padding: 5px 8px; border-radius: 6px;
            background: rgba(99, 102, 241, 0.14); color: #a5b4fc;
            font-size: 10px; font-weight: 800; letter-spacing: 0.5px;
        }
        .badge-ok { background: rgba(16, 185, 129, 0.12); color: #6ee7b7; }
        .badge-err { background: rgba(244, 63, 94, 0.12); color: #fda4af; }
        .log-card pre {
            margin: 10px 0 0; padding: 13px; border-radius: 8px;
            background: rgba(3, 4, 9, 0.75); color: #cbd5e1;
            font-size: 11px; line-height: 1.55; overflow-x: auto;
            white-space: pre-wrap; word-break: break-word;
        }
        .empty {
            padding: 50px 20px; text-align: center; color: var(--text-muted);
            border: 1px dashed var(--border); border-radius: 14px; font-size: 13px;
        }
        .delete-log-btn {
            border: 1px solid rgba(244, 63, 94, 0.35);
            background: rgba(244, 63, 94, 0.10);
            color: #fda4af;
            border-radius: 7px;
            padding: 6px 10px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.4px;
        }
        .delete-log-btn:hover {
            background: rgba(244, 63, 94, 0.22);
            border-color: rgba(244, 63, 94, 0.65);
        }

        .footer {
            margin-top: 38px; padding-top: 18px; border-top: 1px solid var(--border);
            color: #64748b; font-size: 11px; text-align: center;
        }

        @media (max-width: 850px) {
            body { padding: 24px 15px; }
            .workspace-grid { grid-template-columns: 1fr; }
            .nav-bar { width: 100%; }
            .nav-btn { flex: 1; padding: 10px 8px; }
        }
        @media (max-width: 480px) {
            .brand h1 { font-size: 18px; }
            .brand-icon { width: 42px; height: 42px; }
            .url-row { flex-direction: column; }
            .url-row select { width: 100%; }
            .card { padding: 16px; }
        }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
    <div class="aurora-layer"></div>
    <div class="cyber-grid"></div>
    <div class="cursor-dot" id="cursorDot"></div>
    <div class="cursor-outline" id="cursorOutline"></div>

    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon">N</div>
                <div>
                    <h1>NexRelay</h1>
                    <p>SERVICENOW INTEGRATION HUB</p>
                </div>
            </div>
            <div class="header-status">
                <span class="status-dot"></span>
                <span>Gateway Online</span>
            </div>
        </header>

        <nav class="nav-bar">
            <button class="nav-btn active" onclick="switchPanel('inbound', this)">Inbound Link</button>
            <button class="nav-btn" onclick="switchPanel('outbound', this)">Outbound HTTP Client</button>
            <button class="nav-btn" onclick="switchPanel('logs', this)">Execution Logs <span id="logCount" style="margin-left: 5px; opacity: 0.7;">0</span></button>
        </nav>

        <section class="workspace-panel active" id="panel-inbound">
            <div class="panel-heading">
                <h2>Inbound Data Gateway</h2>
                <p>Securely receive and inspect payloads pushed from your ServiceNow instance.</p>
            </div>
            <div class="workspace-grid">
                <div class="card">
                    <h3>Endpoint Configuration</h3>
                    <div class="field">
                        <label>Public Inbound Endpoint</label>
                        <div class="endpoint-box" id="inboundEndpoint">Loading endpoint...</div>
                        <p class="helper-text">Configure this URL in your ServiceNow REST Message or outbound integration.</p>
                    </div>
                    <div class="field">
                        <label>Authentication Header</label>
                        <div class="endpoint-box">Authorization: Bearer sn_nex_your_secret_token</div>
                        <p class="helper-text">Requests must include a Bearer token beginning with the configured NexRelay prefix.</p>
                    </div>
                </div>
                <div class="card">
                    <h3>Gateway Status</h3>
                    <div class="endpoint-box">
                        <strong style="color: #6ee7b7;">● Listening</strong><br><br>
                        Method: POST<br>
                        Path: /api/v1/servicenow/inbound<br>
                        Content-Type: application/json
                    </div>
                    <p class="helper-text">Incoming requests are validated, recorded, and displayed in Execution Logs.</p>
                </div>
            </div>
        </section>

        <section class="workspace-panel" id="panel-outbound">
            <div class="panel-heading">
                <h2>Outbound HTTP Client</h2>
                <p>Send authenticated REST API requests from NexRelay to your ServiceNow instance.</p>
            </div>
            <div class="workspace-grid">
                <div class="card">
                    <h3>Request Builder</h3>
                    <div class="url-row field">
                        <select id="httpMethod" onchange="toggleBodyState()">
                            <option>GET</option>
                            <option>POST</option>
                            <option>PUT</option>
                            <option>PATCH</option>
                            <option>DELETE</option>
                        </select>
                        <input type="text" id="httpUrl" placeholder="https://your-instance.service-now.com/api/now/table/incident">
                    </div>

                    <div class="pm-tabs">
                        <button class="pm-tab active" onclick="switchPmTab('auth', this)">Authorization</button>
                        <button class="pm-tab" onclick="switchPmTab('headers', this)">Headers</button>
                        <button class="pm-tab" onclick="switchPmTab('body', this)">Body</button>
                    </div>

                    <div class="pm-panel active" id="pm-auth">
                        <div class="field">
                            <label>Authentication Type</label>
                            <select id="authType" onchange="updateAuthFields()">
                                <option value="none">No Auth</option>
                                <option value="basic">Basic Auth</option>
                                <option value="bearer">Bearer Token</option>
                            </select>
                        </div>
                        <div class="auth-fields" id="basicAuthFields">
                            <div class="field">
                                <label>ServiceNow Username</label>
                                <input type="text" id="basicUser" placeholder="admin">
                            </div>
                            <div class="field">
                                <label>ServiceNow Password</label>
                                <input type="password" id="basicPass" placeholder="••••••••">
                            </div>
                        </div>
                        <div class="auth-fields" id="bearerAuthField">
                            <div class="field">
                                <label>Bearer Token</label>
                                <input type="password" id="bearerToken" placeholder="Enter access token">
                            </div>
                        </div>
                        <p class="helper-text">Credentials are sent to the selected ServiceNow endpoint by the NexRelay server.</p>
                    </div>

                    <div class="pm-panel" id="pm-headers">
                        <div class="field">
                            <label>Custom Request Headers</label>
                            <div id="headersList">
                                <div class="header-row">
                                    <input type="text" placeholder="Key" class="h-key" value="Accept">
                                    <input type="text" placeholder="Value" class="h-val" value="application/json">
                                    <button type="button" class="icon-btn" onclick="this.parentElement.remove()">&times;</button>
                                </div>
                            </div>
                            <button type="button" class="btn btn-secondary" onclick="addHeaderRow()">+ Add Header</button>
                        </div>
                    </div>

                    <div class="pm-panel" id="pm-body">
                        <div class="field">
                            <label>Request Body (JSON)</label>
                            <textarea id="httpBody" spellcheck="false" placeholder='{"short_description": "Test incident from NexRelay"}'></textarea>
                            <p class="helper-text">Used for POST, PUT, and PATCH requests. Enter valid JSON.</p>
                        </div>
                    </div>

                    <button class="btn" id="send-btn" style="width: 100%; margin-top: 10px;" onclick="sendOutboundRequest()">Send Request</button>
                </div>

                <div class="card">
                    <h3>Request Information</h3>
                    <div class="endpoint-box">
                        <strong style="color: #7dd3fc;">ServiceNow Table API Example</strong><br><br>
                        POST<br>
                        https://your-instance.service-now.com/api/now/table/incident<br><br>
                        <span style="color: #94a3b8;">Creates a new incident record when the ServiceNow API accepts the request.</span>
                    </div>
                    <p class="helper-text">Use your own ServiceNow instance URL and credentials. The authenticated request is forwarded by the NexRelay server.</p>
                </div>
            </div>
        </section>

        <section class="workspace-panel" id="panel-logs">
            <div class="panel-heading">
                <h2>Execution History</h2>
                <p>Review inbound payloads and outbound ServiceNow API responses.</p>
            </div>
            <div class="logs-container" id="logsContainer">
                <div class="empty">Loading execution history...</div>
            </div>
        </section>

        <div class="footer">
            NexRelay Integration Hub · ServiceNow REST API Gateway
        </div>
    </div>

    <script>
        // Dynamic public endpoint display
        document.getElementById('inboundEndpoint').innerText = window.location.origin + '/api/v1/servicenow/inbound';

        // Custom cursor tracking
        const cursorDot = document.getElementById('cursorDot');
        const cursorOutline = document.getElementById('cursorOutline');

        document.addEventListener('mousemove', (e) => {
            cursorDot.style.left = e.clientX + 'px';
            cursorDot.style.top = e.clientY + 'px';
            cursorOutline.style.left = e.clientX + 'px';
            cursorOutline.style.top = e.clientY + 'px';
        });

        function bindHoverListeners() {
            document.querySelectorAll('button, input, select, textarea, a, .nav-btn, .pm-tab').forEach(el => {
                if (el.dataset.hoverBound) return;
                el.dataset.hoverBound = 'true';
                el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
                el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
            });
        }
        bindHoverListeners();

        // Animated constellation mesh
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let particles = [];

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            particles = [];
            const count = Math.min(65, Math.floor((canvas.width * canvas.height) / 18000));
            for (let i = 0; i < count; i++) {
                particles.push({
                    x: Math.random() * canvas.width,
                    y: Math.random() * canvas.height,
                    vx: (Math.random() - 0.5) * 0.35,
                    vy: (Math.random() - 0.5) * 0.35,
                    radius: Math.random() * 1.5 + 0.5
                });
            }
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        function animateMesh() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            for (let i = 0; i < particles.length; i++) {
                const p = particles[i];
                p.x += p.vx;
                p.y += p.vy;
                if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(129, 140, 248, 0.7)';
                ctx.fill();

                for (let j = i + 1; j < particles.length; j++) {
                    const q = particles[j];
                    const dx = p.x - q.x;
                    const dy = p.y - q.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 145) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(q.x, q.y);
                        ctx.strokeStyle = `rgba(99, 102, 241, ${0.13 * (1 - dist / 145)})`;
                        ctx.lineWidth = 0.7;
                        ctx.stroke();
                    }
                }
            }
            requestAnimationFrame(animateMesh);
        }
        animateMesh();

        // Panel Display Switcher
        function switchPanel(panelId, btn) {
            document.querySelectorAll('.workspace-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('panel-' + panelId).classList.add('active');
            btn.classList.add('active');
            if (panelId === 'logs') loadLogs();
        }

        function switchPmTab(panel, btn) {
            document.querySelectorAll('.pm-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.pm-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('pm-' + panel).classList.add('active');
        }

        function updateAuthFields() {
            const type = document.getElementById('authType').value;
            const basicFields = document.getElementById('basicAuthFields');
            const bearerField = document.getElementById('bearerAuthField');

            if (type === 'basic') {
                basicFields.style.display = 'block';
                bearerField.style.display = 'none';
            } else if (type === 'bearer') {
                basicFields.style.display = 'none';
                bearerField.style.display = 'block';
            } else {
                basicFields.style.display = 'none';
                bearerField.style.display = 'none';
            }
        }

        function addHeaderRow() {
            const row = document.createElement('div');
            row.className = 'header-row';
            row.innerHTML = \`
                <input type="text" placeholder="Key" class="h-key" />
                <input type="text" placeholder="Value" class="h-val" />
                <button type="button" class="icon-btn" onclick="this.parentElement.remove()">&times;</button>
            \`;
            document.getElementById('headersList').appendChild(row);
            bindHoverListeners();
        }

        function toggleBodyState() {
            const method = document.getElementById('httpMethod').value;
            const bodyField = document.getElementById('httpBody');
            bodyField.disabled = (method === 'GET' || method === 'DELETE');
        }

        let inboundData = [];
        let outboundData = [];

        async function loadLogs() {
            try {
                const response = await fetch('/api/v1/servicenow/logs');
                if (!response.ok) throw new Error('Unable to load execution history.');
                const data = await response.json();
                inboundData = Array.isArray(data.inbound) ? data.inbound : [];
                outboundData = Array.isArray(data.outbound) ? data.outbound : [];
                updateLogCount();
                renderLogs();
            } catch (error) {
                console.error('[NexRelay] Log loading failed:', error);
            }
        }

        async function deleteLog(direction, id) {
            if (!confirm('Delete this NexRelay history entry? This will not delete the actual ServiceNow record.')) return;

            try {
                const response = await fetch('/api/v1/servicenow/logs/' + direction + '/' + encodeURIComponent(id), {
                    method: 'DELETE'
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.message || 'Delete failed.');
                await loadLogs();
            } catch (error) {
                alert(error.message);
            }
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, character => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            })[character]);
        }

        function updateLogCount() {
            const total = inboundData.length + outboundData.length;
            document.getElementById('logCount').innerText = total;
        }

        let sendingRequest = false;

        async function sendOutboundRequest() {
            if (sendingRequest) return;
            const url = document.getElementById('httpUrl').value.trim();
            if (!url) {
                alert('Validation Error: Please enter a target ServiceNow endpoint URL.');
                return;
            }

            const method = document.getElementById('httpMethod').value;
            const authType = document.getElementById('authType').value;
            const basicUser = document.getElementById('basicUser').value;
            const basicPass = document.getElementById('basicPass').value;
            const bearerToken = document.getElementById('bearerToken').value;
            const rawBody = document.getElementById('httpBody').value;

            const headers = {};
            document.querySelectorAll('#headersList .header-row').forEach(row => {
                const k = row.querySelector('.h-key').value.trim();
                const v = row.querySelector('.h-val').value.trim();
                if (k) headers[k] = v;
            });

            let parsedBody = null;
            if (['POST', 'PUT', 'PATCH'].includes(method) && rawBody.trim()) {
                try {
                    parsedBody = JSON.parse(rawBody);
                } catch (e) {
                    alert('Syntax Error: Request body contains invalid JSON format.');
                    return;
                }
            }

            sendingRequest = true;
            const btn = document.getElementById('send-btn');
            btn.disabled = true;
            btn.innerText = 'Dispatching...';

            try {
                const res = await fetch('/api/v1/servicenow/outbound', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method, url, authType, basicUser, basicPass, bearerToken, headers, body: parsedBody })
                });
                const data = await res.json();
                if (data.record) {
                    await loadLogs();
                    document.querySelector('.nav-btn:nth-child(3)').click();
                } else {
                    alert(data.message || 'The outbound request could not be completed.');
                }
            } catch (err) {
                console.error(err);
            } finally {
                sendingRequest = false;
                btn.disabled = false;
                btn.innerText = 'Send Request';
            }
        }

        function renderLogs() {
            const container = document.getElementById('logsContainer');
            const allLogs = [...outboundData, ...inboundData];

            if (!allLogs.length) {
                container.innerHTML = \`<div class="empty">No execution logs recorded yet.</div>\`;
                return;
            }

            container.innerHTML = allLogs.map(item => {
                const safeId = escapeHtml(item.id);
                const safeTimestamp = escapeHtml(item.timestamp);

                if (item.direction === 'INBOUND') {
                    return \`
                        <div class="log-card">
                            <div class="log-meta">
                                <div>
                                    <span class="badge">SERVICENOW INBOUND</span>
                                    <strong style="margin-left: 8px; color: #fff;">\${safeId}</strong>
                                </div>
                                <div style="display:flex; align-items:center; gap:12px;">
                                    <span style="color: var(--text-muted);">\${safeTimestamp}</span>
                                    <button class="delete-log-btn" onclick="deleteLog('inbound', '\${safeId}')">Delete</button>
                                </div>
                            </div>
                            <pre>\${escapeHtml(JSON.stringify(item.payload, null, 2))}</pre>
                        </div>
                    \`;
                } else {
                    const isSuccess = item.statusCode >= 200 && item.statusCode < 300;
                    return \`
                        <div class="log-card">
                            <div class="log-meta">
                                <div>
                                    <span class="badge">\${escapeHtml(item.method)}</span>
                                    <span class="badge \${isSuccess ? 'badge-ok' : 'badge-err'}" style="margin-left: 6px;">\${escapeHtml(item.status)}</span>
                                    <span style="margin-left: 8px; color: var(--text-muted); font-size: 11px;">\${escapeHtml(item.durationMs)} ms</span>
                                </div>
                                <div style="display:flex; align-items:center; gap:12px;">
                                    <span style="color: var(--text-muted);">\${safeTimestamp}</span>
                                    <button class="delete-log-btn" onclick="deleteLog('outbound', '\${safeId}')">Delete</button>
                                </div>
                            </div>
                            <div style="font-family: monospace; font-size: 12px; color: var(--cyan); margin-bottom: 8px; word-break: break-all;">\${escapeHtml(item.url)}</div>
                            <label style="margin-top: 8px;">Response Payload</label>
                            <pre>\${escapeHtml(JSON.stringify(item.responsePayload, null, 2))}</pre>
                        </div>
                    \`;
                }
            }).join('');
        }

        // Load previously saved history when the dashboard opens.
        loadLogs();
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`NexRelay Masterpiece ServiceNow Integration Hub running on port ${PORT}`);
});
