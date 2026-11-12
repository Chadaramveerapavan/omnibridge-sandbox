const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Cryptographically Secure High-Entropy Token for Inbound ServiceNow Rest Messages
const SECURE_API_KEY = "sn_nex_" + crypto.randomBytes(32).toString('hex');
console.log(`[Security] Generated ServiceNow Inbound Bearer Token: ${SECURE_API_KEY}`);

app.use(cors());
app.use(bodyParser.json());

let inboundLogs = [];
let outboundLogs = [];

// 1. ServiceNow Inbound REST Endpoint
app.post('/api/v1/servicenow/inbound', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Authentication failed: The provided Bearer token is invalid or missing.' 
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
    console.log(`[ServiceNow Inbound] ID: ${syncId}`);

    res.status(200).json({
        status: 'Success',
        message: 'Inbound ServiceNow payload successfully ingested.',
        record: inboundEntry
    });
});

// 2. Postman-Style Outbound HTTP Proxy with Diagnostic Precision
app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const { method, url, authType, authValue, headers, body } = req.body;

    if (!url || !method) {
        return res.status(400).json({ 
            status: 'Error', 
            message: 'Validation Error: Both HTTP Method and Target Endpoint URL are required.' 
        });
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

    if (authType === 'basic' && authValue) {
        requestHeaders['Authorization'] = 'Basic ' + Buffer.from(authValue).toString('base64');
    } else if (authType === 'bearer' && authValue) {
        requestHeaders['Authorization'] = `Bearer ${authValue}`;
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
        const response = await fetch(url, fetchOptions);
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
            diagnosticAdvice: 'Verify that your ServiceNow Personal Developer Instance (PDI) is active, online, and not hibernating. Check firewall rules and ensure the URL prefix matches standard instance routing.'
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
        requestPayload: fetchOptions.body ? JSON.parse(fetchOptions.body) : null,
        responsePayload: responseData
    };

    outboundLogs.unshift(outboundEntry);
    console.log(`[ServiceNow Outbound] ${method.toUpperCase()} ${url} -> ${responseStatus} (${durationMs}ms)`);

    res.status(200).json({
        status: 'Completed',
        record: outboundEntry
    });
});

// 3. Elite Masterpiece Frontend (Classic Obsidian-Emerald Theme + Smooth Background & Cursor Animations)
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexRelay | Masterpiece ServiceNow Integration Hub</title>
    <style>
        :root {
            --bg: #030706;
            --surface: #0a1310;
            --surface-card: #0f1c18;
            --surface-elevated: #162622;
            --border: rgba(16, 185, 129, 0.15);
            --border-hover: rgba(16, 185, 129, 0.35);
            --emerald: #10b981;
            --emerald-glow: rgba(16, 185, 129, 0.25);
            --emerald-bright: #34d399;
            --accent-blue: #38bdf8;
            --danger: #f43f5e;
            --warning: #fbbf24;
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

        /* Ambient Dynamic Background Glow Animation */
        .ambient-bg {
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            pointer-events: none;
            z-index: -1;
            background: 
                radial-gradient(circle at 15% 20%, rgba(16, 185, 129, 0.07) 0%, transparent 40%),
                radial-gradient(circle at 85% 80%, rgba(56, 189, 248, 0.05) 0%, transparent 45%);
            animation: ambientShift 14s ease-in-out infinite alternate;
        }
        @keyframes ambientShift {
            0% { transform: scale(1) translate(0, 0); }
            100% { transform: scale(1.06) translate(-15px, 15px); }
        }

        /* Custom Pro Cursor */
        .cursor-dot {
            position: fixed; top: 0; left: 0; width: 6px; height: 6px;
            background: var(--emerald-bright); border-radius: 50%;
            pointer-events: none; z-index: 99999;
            transform: translate(-50%, -50%);
            transition: transform 0.1s ease, background 0.2s ease;
            box-shadow: 0 0 10px var(--emerald);
        }
        .cursor-outline {
            position: fixed; top: 0; left: 0; width: 36px; height: 36px;
            border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 50%;
            pointer-events: none; z-index: 99998;
            transform: translate(-50%, -50%);
            transition: width 0.25s ease, height 0.25s ease, border-color 0.25s ease, background 0.25s ease;
            background: rgba(16, 185, 129, 0.02);
        }
        body.hovering .cursor-outline {
            width: 52px; height: 52px;
            border-color: var(--emerald);
            background: rgba(16, 185, 129, 0.08);
        }

        .container { max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }

        /* Smooth Entrance */
        @keyframes eliteFadeUp {
            from { opacity: 0; transform: translateY(18px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animate-in { animation: eliteFadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards; }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 28px;
        }
        .brand h1 {
            margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;
            display: flex; align-items: center; gap: 10px; color: #fff;
        }
        .brand h1 span { color: var(--emerald); text-shadow: 0 0 20px var(--emerald-glow); }
        .brand p { margin: 6px 0 0 0; font-size: 13px; color: var(--text-muted); }

        .status-badge {
            display: flex; align-items: center; gap: 9px;
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--emerald-bright);
            padding: 7px 16px; border-radius: 999px;
            font-size: 12px; font-weight: 600;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
        }
        .status-dot {
            width: 8px; height: 8px; background: var(--emerald); border-radius: 50%;
            animation: pulseDot 2s infinite;
        }
        @keyframes pulseDot {
            0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            50% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        }

        /* Navigation Bar (Single Active Tab View) */
        .nav-tabs {
            display: flex; gap: 10px; margin-bottom: 28px;
        }
        .nav-btn {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 11px 22px; border-radius: 9px;
            font-size: 13px; font-weight: 600;
            transition: all 0.25s ease;
        }
        .nav-btn:hover { border-color: var(--border-hover); color: #fff; }
        .nav-btn.active {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.18), rgba(16, 185, 129, 0.05));
            border-color: var(--emerald);
            color: var(--emerald-bright);
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.15);
        }

        .workspace-panel { display: none; }
        .workspace-panel.active { display: block; animation: eliteFadeUp 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards; }

        .card {
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 26px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            transition: border-color 0.3s ease;
        }
        .card:hover { border-color: var(--border-hover); }
        .card h2 { margin: 0 0 6px 0; font-size: 16px; font-weight: 600; color: #fff; }
        .card .sub { font-size: 13px; color: var(--text-muted); margin: 0 0 20px 0; }

        label {
            display: block; font-size: 11px; font-weight: 700; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 7px;
        }
        input, select, textarea {
            width: 100%; background: var(--bg); border: 1px solid var(--border);
            color: var(--text-main); padding: 11px 14px; border-radius: 8px;
            font-size: 13px; margin-bottom: 16px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        input:focus, select:focus, textarea:focus {
            outline: none; border-color: var(--emerald);
            box-shadow: 0 0 0 3px var(--emerald-glow);
        }
        textarea { font-family: ui-monospace, monospace; font-size: 12px; resize: vertical; }

        /* Postman Bar */
        .url-bar { display: flex; gap: 10px; margin-bottom: 18px; }
        .url-bar select { width: 130px; margin-bottom: 0; font-weight: 700; color: var(--emerald-bright); }
        .url-bar input { flex: 1; margin-bottom: 0; font-family: ui-monospace, monospace; font-size: 12px; }
        .url-bar button { width: auto; padding: 0 26px; white-space: nowrap; margin-bottom: 0; }

        .pm-tabs { display: flex; gap: 18px; border-bottom: 1px solid var(--border); margin-bottom: 18px; }
        .pm-tab {
            background: none; border: none; color: var(--text-muted); font-size: 12px; font-weight: 600;
            padding: 8px 2px 12px 2px; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s ease;
        }
        .pm-tab.active { color: var(--emerald-bright); border-bottom-color: var(--emerald); }
        .pm-panel { display: none; }
        .pm-panel.active { display: block; animation: eliteFadeUp 0.3s ease; }

        .header-row { display: grid; grid-template-columns: 1fr 1fr 38px; gap: 10px; margin-bottom: 10px; }
        .header-row input { margin-bottom: 0; font-size: 12px; padding: 8px 12px; }
        .icon-btn {
            background: var(--surface-elevated); border: 1px solid var(--border); color: var(--text-muted);
            border-radius: 8px; cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center;
        }
        .icon-btn:hover { color: var(--danger); border-color: var(--danger); }

        .btn-primary {
            width: 100%; background: linear-gradient(135deg, var(--emerald), #059669);
            color: #03110c; border: none; padding: 12px 18px; border-radius: 9px;
            font-weight: 700; font-size: 13px; cursor: pointer;
            box-shadow: 0 4px 15px var(--emerald-glow);
            transition: transform 0.2s ease, filter 0.2s ease;
        }
        .btn-primary:hover:not(:disabled) { filter: brightness(1.1); transform: translateY(-1px); }
        .btn-primary:disabled { background: var(--surface-elevated); color: var(--text-muted); cursor: not-allowed; box-shadow: none; }

        /* Log Cards */
        .log-card {
            background: var(--surface-card); border: 1px solid var(--border); border-radius: 12px;
            padding: 20px; margin-bottom: 16px; animation: eliteFadeUp 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .log-meta { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; font-size: 12px; }
        .badge {
            padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px;
            background: rgba(56, 189, 248, 0.15); color: var(--accent-blue);
        }
        .badge-ok { background: rgba(16, 185, 129, 0.15); color: var(--emerald-bright); }
        .badge-err { background: rgba(244, 63, 94, 0.15); color: var(--danger); }

        pre {
            background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
            padding: 14px; margin: 10px 0 0 0; font-size: 12px; color: #cbd5e1; overflow-x: auto;
        }
        .empty {
            text-align: center; padding: 50px; color: var(--text-muted); font-size: 13px;
            background: var(--surface-card); border: 1px dashed var(--border); border-radius: 12px;
        }
    </style>
</head>
<body>
    <div class="ambient-bg"></div>
    <div class="cursor-dot" id="cursorDot"></div>
    <div class="cursor-outline" id="cursorOutline"></div>

    <div class="container animate-in">
        <header>
            <div class="brand">
                <h1>Nex<span>Relay</span> · ServiceNow Integration Hub</h1>
                <p>Masterpiece Bi-Directional Table API & REST Proxy</p>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                Secure Gateway Online
            </div>
        </header>

        <!-- Classic Navigation Tabs (Single Tab View) -->
        <div class="nav-tabs">
            <button class="nav-btn active" onclick="switchPanel('inbound', this)">Inbound Listener</button>
            <button class="nav-btn" onclick="switchPanel('outbound', this)">Outbound HTTP Client</button>
            <button class="nav-btn" onclick="switchPanel('logs', this)">Execution Logs (<span id="logCount">0</span>)</button>
        </div>

        <!-- Panel 1: Inbound Listener -->
        <div id="panel-inbound" class="workspace-panel active">
            <div class="card" style="max-width: 650px;">
                <h2>Inbound REST Simulator</h2>
                <p class="sub">Simulate an incoming ServiceNow event payload (single trigger enforced per session).</p>

                <label>ServiceNow Table</label>
                <select id="inbTable">
                    <option value="incident">Incident [incident]</option>
                    <option value="change_request">Change Request [change_request]</option>
                    <option value="problem">Problem [problem]</option>
                    <option value="sc_req_item">Requested Item [sc_req_item]</option>
                </select>

                <label>Trigger Event</label>
                <select id="inbEvent">
                    <option value="record.inserted">After Insert (Created)</option>
                    <option value="record.updated">After Update (Modified)</option>
                </select>

                <label>Secured Inbound Endpoint URL</label>
                <input type="text" readonly value="/api/v1/servicenow/inbound" style="color: var(--text-muted); font-family: monospace; font-size: 12px;" />

                <button class="btn-primary" id="inbound-btn" onclick="triggerInboundOnce()">Send Inbound Payload</button>
            </div>
        </div>

        <!-- Panel 2: Outbound HTTP Client -->
        <div id="panel-outbound" class="workspace-panel">
            <div class="card">
                <h2>Postman-Grade Outbound HTTP Proxy</h2>
                <p class="sub">Execute authenticated requests against your ServiceNow Table API or Scripted REST APIs.</p>

                <div class="url-bar">
                    <select id="httpMethod" onchange="toggleBodyState()">
                        <option value="GET">GET</option>
                        <option value="POST" selected>POST</option>
                        <option value="PUT">PUT</option>
                        <option value="PATCH">PATCH</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                    <input type="url" id="httpUrl" placeholder="https://dev12345.service-now.com/api/now/table/incident" required />
                    <button class="btn-primary" id="send-btn" onclick="sendOutboundRequest()">Send Request</button>
                </div>

                <div class="pm-tabs">
                    <button class="pm-tab active" onclick="switchPmTab('auth', this)">Authorization</button>
                    <button class="pm-tab" onclick="switchPmTab('headers', this)">Headers</button>
                    <button class="pm-tab" onclick="switchPmTab('body', this)">Body (JSON)</button>
                </div>

                <!-- Auth Sub-panel -->
                <div id="pm-auth" class="pm-panel active">
                    <label>Auth Type</label>
                    <select id="authType" onchange="updateAuthPlaceholder()">
                        <option value="basic">Basic Auth (username:password)</option>
                        <option value="bearer">Bearer Token (OAuth 2.0)</option>
                        <option value="none">No Auth</option>
                    </select>
                    <label id="authLabel">Credentials (username:password)</label>
                    <input type="password" id="authValue" placeholder="admin:your_pdi_password" />
                </div>

                <!-- Headers Sub-panel -->
                <div id="pm-headers" class="pm-panel">
                    <div id="headersList">
                        <div class="header-row">
                            <input type="text" placeholder="Key" value="Accept" class="h-key" />
                            <input type="text" placeholder="Value" value="application/json" class="h-val" />
                            <button type="button" class="icon-btn" onclick="this.parentElement.remove()">&times;</button>
                        </div>
                    </div>
                    <button type="button" class="nav-btn" style="padding: 7px 14px; font-size: 12px; margin-top: 6px;" onclick="addHeaderRow()">+ Add Header</button>
                </div>

                <!-- Body Sub-panel -->
                <div id="pm-body" class="pm-panel">
                    <label>Raw JSON Body</label>
                    <textarea id="httpBody" rows="6">{
  "short_description": "Elite automated incident created via NexRelay Hub",
  "urgency": "2",
  "impact": "2",
  "category": "software"
}</textarea>
                </div>
            </div>
        </div>

        <!-- Panel 3: Execution Logs -->
        <div id="panel-logs" class="workspace-panel">
            <div class="card" style="background: transparent; border: none; padding: 0; box-shadow: none;">
                <h2>Execution History & Diagnostics</h2>
                <p class="sub">Real-time audit trail of inbound triggers and outbound proxy responses.</p>
                <div id="logsContainer">
                    <div class="empty">No execution logs recorded in this session.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Pro Custom Cursor Movement & Hover Effect
        const dot = document.getElementById('cursorDot');
        const outline = document.getElementById('cursorOutline');
        let mouseX = 0, mouseY = 0, outlineX = 0, outlineY = 0;

        window.addEventListener('mousemove', e => {
            mouseX = e.clientX; mouseY = e.clientY;
            dot.style.left = mouseX + 'px';
            dot.style.top = mouseY + 'px';
        });

        function renderCursor() {
            outlineX += (mouseX - outlineX) * 0.2;
            outlineY += (mouseY - outlineY) * 0.2;
            outline.style.left = outlineX + 'px';
            outline.style.top = outlineY + 'px';
            requestAnimationFrame(renderCursor);
        }
        renderCursor();

        document.querySelectorAll('button, input, select, textarea').forEach(el => {
            el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
            el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
        });

        // Single Tab Display Controller
        function switchPanel(panelId, btn) {
            document.querySelectorAll('.workspace-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('panel-' + panelId).classList.add('active');
            btn.classList.add('active');
        }

        function switchPmTab(panel, btn) {
            document.querySelectorAll('.pm-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.pm-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('pm-' + panel).classList.add('active');
        }

        function updateAuthPlaceholder() {
            const type = document.getElementById('authType').value;
            const label = document.getElementById('authLabel');
            const input = document.getElementById('authValue');
            if (type === 'basic') {
                label.innerText = 'Credentials (username:password)';
                input.placeholder = 'admin:your_pdi_password';
                input.disabled = false;
            } else if (type === 'bearer') {
                label.innerText = 'OAuth Access Token';
                input.placeholder = 'Paste ServiceNow OAuth Bearer Token';
                input.disabled = false;
            } else {
                label.innerText = 'No Authorization Required';
                input.placeholder = 'Disabled';
                input.disabled = true;
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
        }

        function toggleBodyState() {
            const method = document.getElementById('httpMethod').value;
            const bodyField = document.getElementById('httpBody');
            bodyField.disabled = (method === 'GET' || method === 'DELETE');
        }

        let inboundTriggered = false;
        let inboundData = [];
        let outboundData = [];

        function updateLogCount() {
            const total = inboundData.length + outboundData.length;
            document.getElementById('logCount').innerText = total;
        }

        // Single-Trigger Inbound
        async function triggerInboundOnce() {
            if (inboundTriggered) return;
            inboundTriggered = true;

            const btn = document.getElementById('inbound-btn');
            btn.disabled = true;
            btn.innerText = 'Inbound Payload Sent (1/1)';

            const table = document.getElementById('inbTable').value;
            const event = document.getElementById('inbEvent').value;

            try {
                const res = await fetch('/api/v1/servicenow/inbound', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + '${SECURE_API_KEY}'
                    },
                    body: JSON.stringify({
                        instance: 'dev-servicenow.service-now.com',
                        table,
                        event,
                        number: 'INC00' + Math.floor(10000 + Math.random() * 90000),
                        short_description: 'ServiceNow inbound webhook simulation payload',
                        state: 'New',
                        timestamp: new Date().toISOString()
                    })
                });
                const data = await res.json();
                if (res.ok && data.record) {
                    inboundData.unshift(data.record);
                    updateLogCount();
                    renderLogs();
                }
            } catch (err) {
                console.error(err);
            }
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
            const authValue = document.getElementById('authValue').value;
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
                    body: JSON.stringify({ method, url, authType, authValue, headers, body: parsedBody })
                });
                const data = await res.json();
                if (res.ok && data.record) {
                    outboundData.unshift(data.record);
                    updateLogCount();
                    renderLogs();
                    // Automatically switch to logs to show result
                    document.querySelector('.nav-btn:nth-child(3)').click();
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
                container.innerHTML = \`<div class="empty">No execution logs recorded in this session.</div>\`;
                return;
            }

            container.innerHTML = allLogs.map(item => {
                if (item.direction === 'INBOUND') {
                    return \`
                        <div class="log-card">
                            <div class="log-meta">
                                <div>
                                    <span class="badge">SERVICENOW INBOUND</span>
                                    <strong style="margin-left: 8px; color: #fff;">\${item.id}</strong>
                                </div>
                                <span style="color: var(--text-muted);">\${item.timestamp}</span>
                            </div>
                            <pre>\${JSON.stringify(item.payload, null, 2)}</pre>
                        </div>
                    \`;
                } else {
                    const isSuccess = item.statusCode >= 200 && item.statusCode < 300;
                    return \`
                        <div class="log-card">
                            <div class="log-meta">
                                <div>
                                    <span class="badge">\${item.method}</span>
                                    <span class="badge \${isSuccess ? 'badge-ok' : 'badge-err'}" style="margin-left: 6px;">\${item.status}</span>
                                    <span style="margin-left: 8px; color: var(--text-muted); font-size: 11px;">\${item.durationMs} ms</span>
                                </div>
                                <span style="color: var(--text-muted);">\${item.timestamp}</span>
                            </div>
                            <div style="font-family: monospace; font-size: 12px; color: var(--accent-blue); margin-bottom: 8px; word-break: break-all;">\${item.url}</div>
                            <label style="margin-top: 8px;">Response Payload</label>
                            <pre>\${JSON.stringify(item.responsePayload, null, 2)}</pre>
                        </div>
                    \`;
                }
            }).join('');
        }
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`NexRelay Masterpiece ServiceNow Integration Hub running on port ${PORT}`);
});