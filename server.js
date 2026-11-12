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

// 1. ServiceNow Inbound REST Endpoint (ServiceNow Business Rule / REST Message -> Hub)
app.post('/api/v1/servicenow/inbound', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Unauthorized: Invalid or missing Bearer token' 
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
        message: 'Inbound ServiceNow payload received',
        record: inboundEntry
    });
});

// 2. Postman-Style Outbound HTTP Proxy (Hub -> ServiceNow Table API / Scripted REST API)
app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const { method, url, authType, authValue, headers, body } = req.body;

    if (!url || !method) {
        return res.status(400).json({ status: 'Error', message: 'HTTP Method and ServiceNow Endpoint URL are required.' });
    }

    const syncId = "SN-OUT-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();
    const startTime = Date.now();

    // Build Request Headers
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

    try {
        const response = await fetch(url, fetchOptions);
        durationMs = Date.now() - startTime;
        responseStatus = response.status;
        statusText = response.statusText;

        const rawText = await response.text();
        try {
            responseData = JSON.parse(rawText);
        } catch {
            responseData = rawText || { message: 'No response body returned' };
        }
    } catch (error) {
        durationMs = Date.now() - startTime;
        responseStatus = 502;
        statusText = 'Connection Error';
        responseData = {
            error: error.message,
            hint: 'Ensure your ServiceNow PDI is awake and the instance URL is reachable.'
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

// 3. Clean ServiceNow Integration Hub Frontend
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexRelay | ServiceNow Integration Hub</title>
    <style>
        :root {
            --bg: #070b12;
            --surface: #0f1623;
            --surface-elevated: #161f30;
            --border: rgba(148, 163, 184, 0.14);
            --sn-green: #62d84e;
            --sn-green-glow: rgba(98, 216, 78, 0.18);
            --accent: #38bdf8;
            --danger: #f87171;
            --warning: #fbbf24;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 28px 20px;
            min-height: 100vh;
            line-height: 1.5;
        }
        .container { max-width: 1160px; margin: 0 auto; }

        /* Smooth Entrance Animations */
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(14px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulseGlow {
            0%, 100% { box-shadow: 0 0 0 0 rgba(98, 216, 78, 0.5); }
            50% { box-shadow: 0 0 0 8px rgba(98, 216, 78, 0); }
        }
        @keyframes flowLine {
            to { stroke-dashoffset: -24; }
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            animation: slideUp 0.45s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .brand h1 {
            margin: 0;
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.4px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .brand h1 span { color: var(--sn-green); }
        .brand p { margin: 4px 0 0 0; font-size: 12px; color: var(--text-dim); }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(98, 216, 78, 0.1);
            border: 1px solid rgba(98, 216, 78, 0.3);
            color: var(--sn-green);
            padding: 6px 14px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--sn-green);
            border-radius: 50%;
            animation: pulseGlow 2.2s infinite;
        }

        /* Smooth Architecture Flow Banner */
        .flow-banner {
            background: linear-gradient(180deg, var(--surface) 0%, rgba(15, 22, 35, 0.6) 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 32px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            animation: slideUp 0.55s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .flow-node {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            padding: 12px 20px;
            border-radius: 10px;
            text-align: center;
            min-width: 185px;
            transition: transform 0.25s ease, border-color 0.25s ease;
        }
        .flow-node:hover {
            transform: translateY(-2px);
            border-color: var(--sn-green);
        }
        .flow-node strong { display: block; font-size: 13px; color: #fff; }
        .flow-node span { font-size: 11px; color: var(--text-dim); }
        .flow-node.hub {
            border-color: rgba(98, 216, 78, 0.45);
            box-shadow: 0 0 24px var(--sn-green-glow);
        }
        .flow-connector { flex: 1; display: flex; align-items: center; justify-content: center; padding: 0 12px; }
        .flow-svg { width: 100%; height: 24px; }
        .flow-path {
            stroke: var(--sn-green);
            stroke-width: 2;
            stroke-dasharray: 6 6;
            fill: none;
            animation: flowLine 1.2s linear infinite;
        }

        /* Workspace Layout */
        .grid {
            display: grid;
            grid-template-columns: 380px 1fr;
            gap: 20px;
            margin-bottom: 28px;
            animation: slideUp 0.65s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: border-color 0.25s ease;
        }
        .card:hover { border-color: rgba(148, 163, 184, 0.28); }
        .card h2 {
            margin: 0 0 4px 0;
            font-size: 15px;
            font-weight: 600;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .card .sub { font-size: 12px; color: var(--text-dim); margin: 0 0 16px 0; }

        label {
            display: block;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.4px;
            margin-bottom: 6px;
        }
        input, select, textarea {
            width: 100%;
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 9px 12px;
            border-radius: 7px;
            font-size: 13px;
            margin-bottom: 14px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--sn-green);
            box-shadow: 0 0 0 3px var(--sn-green-glow);
        }
        textarea {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 12px;
            resize: vertical;
        }

        /* Postman URL Bar */
        .url-bar {
            display: flex;
            gap: 8px;
            margin-bottom: 14px;
        }
        .url-bar select {
            width: 115px;
            margin-bottom: 0;
            font-weight: 700;
            color: var(--sn-green);
        }
        .url-bar input {
            flex: 1;
            margin-bottom: 0;
            font-family: ui-monospace, monospace;
            font-size: 12px;
        }
        .url-bar button {
            width: auto;
            padding: 0 20px;
            white-space: nowrap;
        }

        /* Postman Sub-tabs */
        .pm-tabs {
            display: flex;
            gap: 16px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 14px;
        }
        .pm-tab {
            background: none;
            border: none;
            color: var(--text-dim);
            font-size: 12px;
            font-weight: 600;
            padding: 6px 2px 10px 2px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: color 0.2s ease, border-color 0.2s ease;
        }
        .pm-tab.active {
            color: var(--sn-green);
            border-bottom-color: var(--sn-green);
        }
        .pm-panel { display: none; }
        .pm-panel.active { display: block; animation: slideUp 0.25s ease; }

        .header-row {
            display: grid;
            grid-template-columns: 1fr 1fr 32px;
            gap: 8px;
            margin-bottom: 8px;
        }
        .header-row input { margin-bottom: 0; font-size: 12px; padding: 7px 10px; }
        .icon-btn {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            color: var(--text-dim);
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        .icon-btn:hover { color: var(--danger); border-color: var(--danger); }

        .btn-primary {
            width: 100%;
            background: var(--sn-green);
            color: #051108;
            border: none;
            padding: 10px 16px;
            border-radius: 7px;
            font-weight: 700;
            font-size: 13px;
            cursor: pointer;
            transition: transform 0.2s ease, filter 0.2s ease;
        }
        .btn-primary:hover:not(:disabled) {
            filter: brightness(1.08);
            transform: translateY(-1px);
        }
        .btn-primary:disabled {
            background: var(--surface-elevated);
            color: var(--text-dim);
            cursor: not-allowed;
        }

        /* Feed Tabs */
        .feed-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 16px;
        }
        .feed-tabs { display: flex; gap: 8px; }
        .feed-tab {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-dim);
            padding: 7px 14px;
            border-radius: 7px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .feed-tab.active {
            background: rgba(98, 216, 78, 0.12);
            border-color: var(--sn-green);
            color: var(--sn-green);
        }

        .log-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
            animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .log-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            font-size: 12px;
        }
        .badge {
            padding: 3px 8px;
            border-radius: 5px;
            font-weight: 700;
            font-size: 11px;
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent);
        }
        .badge-ok { background: rgba(98, 216, 78, 0.15); color: var(--sn-green); }
        .badge-err { background: rgba(248, 113, 113, 0.15); color: var(--danger); }

        pre {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 7px;
            padding: 12px;
            margin: 8px 0 0 0;
            font-size: 12px;
            color: #cbd5e1;
            overflow-x: auto;
        }
        .empty {
            text-align: center;
            padding: 40px;
            color: var(--text-dim);
            font-size: 13px;
            background: var(--surface);
            border: 1px dashed var(--border);
            border-radius: 10px;
        }
        @media (max-width: 900px) {
            .grid { grid-template-columns: 1fr; }
            .flow-banner { flex-direction: column; gap: 12px; }
            .flow-connector { transform: rotate(90deg); width: 40px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>Nex<span>Relay</span> · ServiceNow Integration Hub</h1>
                <p>Bi-Directional Table API & REST Message Engine</p>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                ServiceNow Listener Ready
            </div>
        </header>

        <!-- Smooth Data Flow Architecture -->
        <div class="flow-banner">
            <div class="flow-node">
                <strong>ServiceNow Instance</strong>
                <span>Inbound REST Message</span>
            </div>
            <div class="flow-connector">
                <svg class="flow-svg" viewBox="0 0 120 24">
                    <line x1="0" y1="12" x2="120" y2="12" class="flow-path" />
                </svg>
            </div>
            <div class="flow-node hub">
                <strong>NexRelay Engine</strong>
                <span>Auth & Payload Router</span>
            </div>
            <div class="flow-connector">
                <svg class="flow-svg" viewBox="0 0 120 24">
                    <line x1="0" y1="12" x2="120" y2="12" class="flow-path" />
                </svg>
            </div>
            <div class="flow-node">
                <strong>ServiceNow Table API</strong>
                <span>Outbound HTTP Client</span>
            </div>
        </div>

        <div class="grid">
            <!-- Left Panel: Single-Trigger Inbound Simulator -->
            <div class="card">
                <h2>Inbound Listener</h2>
                <p class="sub">Simulate an incoming ServiceNow payload (single trigger per session).</p>

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

                <label>Inbound Endpoint</label>
                <input type="text" readonly value="/api/v1/servicenow/inbound" style="color: var(--text-dim); font-family: monospace; font-size: 12px;" />

                <button class="btn-primary" id="inbound-btn" onclick="triggerInboundOnce()">Send Inbound Payload</button>
            </div>

            <!-- Right Panel: Postman-Style Outbound HTTP Client -->
            <div class="card">
                <h2>Outbound HTTP Client (ServiceNow API)</h2>
                <p class="sub">Execute GET, POST, PUT, PATCH, or DELETE requests directly against your ServiceNow PDI.</p>

                <div class="url-bar">
                    <select id="httpMethod" onchange="toggleBodyState()">
                        <option value="GET">GET</option>
                        <option value="POST" selected>POST</option>
                        <option value="PUT">PUT</option>
                        <option value="PATCH">PATCH</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                    <input type="url" id="httpUrl" placeholder="https://dev12345.service-now.com/api/now/table/incident" required />
                    <button class="btn-primary" id="send-btn" onclick="sendOutboundRequest()">Send</button>
                </div>

                <!-- Postman Config Sub-Tabs -->
                <div class="pm-tabs">
                    <button class="pm-tab active" onclick="switchPmTab('auth', this)">Authorization</button>
                    <button class="pm-tab" onclick="switchPmTab('headers', this)">Headers</button>
                    <button class="pm-tab" onclick="switchPmTab('body', this)">Body (JSON)</button>
                </div>

                <!-- Auth Tab -->
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

                <!-- Headers Tab -->
                <div id="pm-headers" class="pm-panel">
                    <div id="headersList">
                        <div class="header-row">
                            <input type="text" placeholder="Key" value="Accept" class="h-key" />
                            <input type="text" placeholder="Value" value="application/json" class="h-val" />
                            <button type="button" class="icon-btn" onclick="this.parentElement.remove()">&times;</button>
                        </div>
                    </div>
                    <button type="button" class="feed-tab" style="margin-top: 4px;" onclick="addHeaderRow()">+ Add Header</button>
                </div>

                <!-- Body Tab -->
                <div id="pm-body" class="pm-panel">
                    <label>Raw JSON Payload</label>
                    <textarea id="httpBody" rows="5">{
  "short_description": "Automated incident created via NexRelay Hub",
  "urgency": "2",
  "impact": "2",
  "category": "software"
}</textarea>
                </div>
            </div>
        </div>

        <!-- Execution Logs -->
        <div class="feed-header">
            <div class="feed-tabs">
                <button class="feed-tab active" id="tab-outbound" onclick="switchFeed('outbound')">Outbound Responses (0)</button>
                <button class="feed-tab" id="tab-inbound" onclick="switchFeed('inbound')">Inbound Payloads (0)</button>
            </div>
        </div>

        <div id="logsContainer">
            <div class="empty">Clean workspace. Send an outbound API request or trigger an inbound payload above.</div>
        </div>
    </div>

    <script>
        let activeFeed = 'outbound';
        let inboundData = [];
        let outboundData = [];
        let inboundTriggered = false;
        let sendingRequest = false;

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
                <input type="text" placeholder="Header Key" class="h-key" />
                <input type="text" placeholder="Header Value" class="h-val" />
                <button type="button" class="icon-btn" onclick="this.parentElement.remove()">&times;</button>
            \`;
            document.getElementById('headersList').appendChild(row);
        }

        function toggleBodyState() {
            const method = document.getElementById('httpMethod').value;
            const bodyField = document.getElementById('httpBody');
            bodyField.disabled = (method === 'GET' || method === 'DELETE');
        }

        function switchFeed(type) {
            activeFeed = type;
            document.getElementById('tab-outbound').classList.toggle('active', type === 'outbound');
            document.getElementById('tab-inbound').classList.toggle('active', type === 'inbound');
            renderLogs();
        }

        function updateCounts() {
            document.getElementById('tab-outbound').innerText = \`Outbound Responses (\${outboundData.length})\`;
            document.getElementById('tab-inbound').innerText = \`Inbound Payloads (\${inboundData.length})\`;
        }

        // Single-Trigger Inbound Execution
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
                    updateCounts();
                    switchFeed('inbound');
                }
            } catch (err) {
                console.error(err);
            }
        }

        // Postman-Style Outbound HTTP Execution
        async function sendOutboundRequest() {
            if (sendingRequest) return;
            const url = document.getElementById('httpUrl').value.trim();
            if (!url) {
                alert('Please enter a ServiceNow endpoint URL.');
                return;
            }

            const method = document.getElementById('httpMethod').value;
            const authType = document.getElementById('authType').value;
            const authValue = document.getElementById('authValue').value;
            const rawBody = document.getElementById('httpBody').value;

            // Collect custom headers
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
                    alert('Invalid JSON in Request Body.');
                    return;
                }
            }

            sendingRequest = true;
            const btn = document.getElementById('send-btn');
            btn.disabled = true;
            btn.innerText = 'Sending...';

            try {
                const res = await fetch('/api/v1/servicenow/outbound', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        method,
                        url,
                        authType,
                        authValue,
                        headers,
                        body: parsedBody
                    })
                });
                const data = await res.json();
                if (res.ok && data.record) {
                    outboundData.unshift(data.record);
                    updateCounts();
                    switchFeed('outbound');
                }
            } catch (err) {
                console.error(err);
            } finally {
                sendingRequest = false;
                btn.disabled = false;
                btn.innerText = 'Send';
            }
        }

        function renderLogs() {
            const container = document.getElementById('logsContainer');
            const list = activeFeed === 'outbound' ? outboundData : inboundData;

            if (!list.length) {
                container.innerHTML = \`<div class="empty">No \${activeFeed} records in this session.</div>\`;
                return;
            }

            if (activeFeed === 'inbound') {
                container.innerHTML = list.map(item => \`
                    <div class="log-card">
                        <div class="log-meta">
                            <div>
                                <span class="badge">SERVICENOW INBOUND</span>
                                <strong style="margin-left: 8px; color: #fff;">\${item.id}</strong>
                            </div>
                            <span style="color: var(--text-dim);">\${item.timestamp}</span>
                        </div>
                        <pre>\${JSON.stringify(item.payload, null, 2)}</pre>
                    </div>
                \`).join('');
            } else {
                container.innerHTML = list.map(item => {
                    const isSuccess = item.statusCode >= 200 && item.statusCode < 300;
                    return \`
                        <div class="log-card">
                            <div class="log-meta">
                                <div>
                                    <span class="badge">\${item.method}</span>
                                    <span class="badge \${isSuccess ? 'badge-ok' : 'badge-err'}" style="margin-left: 6px;">\${item.status}</span>
                                    <span style="margin-left: 8px; color: var(--text-dim); font-size: 11px;">\${item.durationMs} ms</span>
                                </div>
                                <span style="color: var(--text-dim);">\${item.timestamp}</span>
                            </div>
                            <div style="font-family: monospace; font-size: 12px; color: var(--accent); margin-bottom: 8px; word-break: break-all;">\${item.url}</div>
                            <label style="margin-top: 8px;">ServiceNow Response Body</label>
                            <pre>\${JSON.stringify(item.responsePayload, null, 2)}</pre>
                        </div>
                    \`;
                }).join('');
            }
        }
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`NexRelay ServiceNow Integration Hub running on port ${PORT}`);
});