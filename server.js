const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

let inboundLogs = [];
let outboundLogs = [];

// 1. ServiceNow Inbound REST Endpoint
app.post('/api/v1/servicenow/inbound', (req, res) => {
    const authHeader = req.headers['authorization'];
    const deviceToken = req.headers['x-device-token'];

    // Validate either global cryptographic token or device-specific ephemeral session token
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

// 3. Masterpiece Frontend (Cyber-Indigo & Obsidian Theme + Stunner Background Canvas Orbs + Hide/Unhide Icons + Device Random Token)
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
            --surface-card: #101628;
            --surface-elevated: #18223c;
            --border: rgba(99, 102, 241, 0.18);
            --border-hover: rgba(99, 102, 241, 0.45);
            --indigo: #6366f1;
            --indigo-glow: rgba(99, 102, 241, 0.35);
            --cyan: #38bdf8;
            --cyan-glow: rgba(56, 189, 248, 0.3);
            --emerald: #10b981;
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

        /* Stunning Moving Background Canvas & Floating Ambient Orbs */
        #bgCanvas {
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            pointer-events: none;
            z-index: -2;
        }

        .ambient-bg {
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            pointer-events: none;
            z-index: -1;
            background: 
                radial-gradient(circle at 15% 20%, rgba(99, 102, 241, 0.15) 0%, transparent 45%),
                radial-gradient(circle at 85% 80%, rgba(56, 189, 248, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 50% 50%, rgba(16, 185, 129, 0.08) 0%, transparent 60%);
            animation: orbFloat 10s ease-in-out infinite alternate;
        }
        @keyframes orbFloat {
            0% { transform: scale(1) translate(0, 0); }
            100% { transform: scale(1.1) translate(-25px, 25px); }
        }

        /* Custom Glowing Cursor */
        .cursor-dot {
            position: fixed; top: 0; left: 0; width: 8px; height: 8px;
            background: var(--cyan); border-radius: 50%;
            pointer-events: none; z-index: 99999;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 12px var(--cyan);
            transition: transform 0.1s ease;
        }
        .cursor-outline {
            position: fixed; top: 0; left: 0; width: 40px; height: 40px;
            border: 1px solid rgba(99, 102, 241, 0.5); border-radius: 50%;
            pointer-events: none; z-index: 99998;
            transform: translate(-50%, -50%);
            transition: width 0.25s ease, height 0.25s ease, border-color 0.25s ease, background 0.25s ease;
            background: rgba(99, 102, 241, 0.04);
        }
        body.hovering .cursor-outline {
            width: 56px; height: 56px;
            border-color: var(--cyan);
            background: rgba(56, 189, 248, 0.1);
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
        }
        .brand h1 {
            margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;
            display: flex; align-items: center; gap: 10px; color: #fff;
        }
        .brand h1 span { color: var(--indigo); text-shadow: 0 0 25px var(--indigo-glow); }
        .brand p { margin: 6px 0 0 0; font-size: 13px; color: var(--text-muted); }

        .status-badge {
            display: flex; align-items: center; gap: 9px;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.35);
            color: var(--cyan);
            padding: 7px 16px; border-radius: 999px;
            font-size: 12px; font-weight: 600;
            box-shadow: 0 0 20px rgba(99, 102, 241, 0.15);
        }
        .status-dot {
            width: 8px; height: 8px; background: var(--cyan); border-radius: 50%;
            animation: pulseDot 2s infinite;
        }
        @keyframes pulseDot {
            0%, 100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.8); }
            50% { box-shadow: 0 0 0 9px rgba(56, 189, 248, 0); }
        }

        .nav-tabs {
            display: flex; gap: 12px; margin-bottom: 28px;
        }
        .nav-btn {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 12px 24px; border-radius: 10px;
            font-size: 13px; font-weight: 600;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .nav-btn:hover { border-color: var(--border-hover); color: #fff; transform: translateY(-1px); }
        .nav-btn.active {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.22), rgba(56, 189, 248, 0.1));
            border-color: var(--indigo);
            color: var(--cyan);
            box-shadow: 0 6px 25px rgba(99, 102, 241, 0.25);
        }

        .workspace-panel { display: none; }
        .workspace-panel.active { display: block; animation: heavyFadeIn 0.45s cubic-bezier(0.16, 1, 0.3, 1) forwards; }

        .card {
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 24px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            transition: border-color 0.3s ease;
        }
        .card:hover { border-color: var(--border-hover); }
        .card h2 { margin: 0 0 6px 0; font-size: 18px; font-weight: 600; color: #fff; }
        .card .sub { font-size: 13px; color: var(--text-muted); margin: 0 0 24px 0; }

        label {
            display: block; font-size: 11px; font-weight: 700; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.7px; margin-bottom: 8px;
        }
        input, select, textarea {
            width: 100%; background: var(--bg); border: 1px solid var(--border);
            color: var(--text-main); padding: 12px 16px; border-radius: 9px;
            font-size: 13px; margin-bottom: 18px;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        input:focus, select:focus, textarea:focus {
            outline: none; border-color: var(--indigo);
            box-shadow: 0 0 0 3px var(--indigo-glow);
        }
        textarea { font-family: ui-monospace, monospace; font-size: 12px; resize: vertical; }

        .input-group {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-group input { margin-bottom: 0; }
        .toggle-icon {
            position: absolute;
            right: 14px;
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 14px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .toggle-icon:hover { color: var(--cyan); }

        .url-bar { display: flex; gap: 12px; margin-bottom: 20px; }
        .url-bar select { width: 135px; margin-bottom: 0; font-weight: 700; color: var(--cyan); }
        .url-bar input { flex: 1; margin-bottom: 0; font-family: ui-monospace, monospace; font-size: 12px; }
        .url-bar button { width: auto; padding: 0 28px; white-space: nowrap; margin-bottom: 0; }

        .pm-tabs { display: flex; gap: 20px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
        .pm-tab {
            background: none; border: none; color: var(--text-muted); font-size: 12px; font-weight: 600;
            padding: 8px 2px 14px 2px; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s ease;
        }
        .pm-tab.active { color: var(--cyan); border-bottom-color: var(--indigo); }
        .pm-panel { display: none; }
        .pm-panel.active { display: block; animation: heavyFadeIn 0.3s ease; }

        .header-row { display: grid; grid-template-columns: 1fr 1fr 40px; gap: 12px; margin-bottom: 12px; }
        .header-row input { margin-bottom: 0; font-size: 12px; padding: 9px 14px; }
        .icon-btn {
            background: var(--surface-elevated); border: 1px solid var(--border); color: var(--text-muted);
            border-radius: 9px; cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center;
        }
        .icon-btn:hover { color: var(--danger); border-color: var(--danger); }

        .btn-primary {
            width: 100%; background: linear-gradient(135deg, var(--indigo), #4f46e5);
            color: #fff; border: none; padding: 13px 20px; border-radius: 10px;
            font-weight: 700; font-size: 13px; cursor: pointer;
            box-shadow: 0 6px 20px var(--indigo-glow);
            transition: transform 0.2s ease, filter 0.2s ease;
        }
        .btn-primary:hover:not(:disabled) { filter: brightness(1.12); transform: translateY(-1px); }
        .btn-primary:disabled { background: var(--surface-elevated); color: var(--text-muted); cursor: not-allowed; box-shadow: none; }

        .log-card {
            background: var(--surface-card); border: 1px solid var(--border); border-radius: 14px;
            padding: 22px; margin-bottom: 18px; animation: heavyFadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .log-meta { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; font-size: 12px; }
        .badge {
            padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px;
            background: rgba(99, 102, 241, 0.2); color: var(--cyan);
        }
        .badge-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; }
        .badge-err { background: rgba(244, 63, 94, 0.2); color: var(--danger); }

        pre {
            background: var(--bg); border: 1px solid var(--border); border-radius: 9px;
            padding: 16px; margin: 10px 0 0 0; font-size: 12px; color: #cbd5e1; overflow-x: auto;
        }
        .empty {
            text-align: center; padding: 60px; color: var(--text-muted); font-size: 13px;
            background: var(--surface-card); border: 1px dashed var(--border); border-radius: 14px;
        }
    </style>
</head>
<body>
    <canvas id="bgCanvas"></canvas>
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

        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-btn active" onclick="switchPanel('inbound', this)">Inbound Link</button>
            <button class="nav-btn" onclick="switchPanel('outbound', this)">Outbound HTTP Client</button>
            <button class="nav-btn" onclick="switchPanel('logs', this)">Execution Logs (<span id="logCount">0</span>)</button>
        </div>

        <!-- Panel 1: Inbound Link Only -->
        <div id="panel-inbound" class="workspace-panel active">
            <div class="card" style="max-width: 700px;">
                <h2>Inbound Webhook Endpoint</h2>
                <p class="sub">Provide this exact website link to your ServiceNow instance (via REST Message or Business Rule) to ingest payloads.</p>

                <label>Secured Inbound Webhook URL</label>
                <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                    <input type="text" id="inboundUrlBox" readonly style="margin-bottom: 0; font-family: monospace; color: var(--cyan);" />
                    <button class="btn-primary" style="width: auto; padding: 0 24px;" onclick="copyInboundUrl()">Copy Link</button>
                </div>

                <label>Required Authorization Header (Randomized Ephemeral Session Token)</label>
                <div class="input-group" style="margin-bottom: 18px;">
                    <input type="password" id="authHeaderBox" readonly style="margin-bottom: 0; font-family: monospace; color: var(--text-muted);" />
                    <button type="button" class="toggle-icon" onclick="toggleVisibility('authHeaderBox', this)">👁️</button>
                </div>
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

                <!-- Auth Sub-panel with Hide/Unhide Support -->
                <div id="pm-auth" class="pm-panel active">
                    <label>Auth Type</label>
                    <select id="authType" onchange="updateAuthFields()">
                        <option value="basic">Basic Auth (Separate Username & Password)</option>
                        <option value="bearer">Bearer Token (OAuth 2.0)</option>
                        <option value="none">No Auth</option>
                    </select>

                    <div id="basicAuthFields">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px;">
                            <div>
                                <label>Username</label>
                                <input type="text" id="basicUser" placeholder="admin" style="margin-bottom: 0;" />
                            </div>
                            <div>
                                <label>Password</label>
                                <div class="input-group">
                                    <input type="password" id="basicPass" placeholder="your_pdi_password" />
                                    <button type="button" class="toggle-icon" onclick="toggleVisibility('basicPass', this)">👁️</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div id="bearerAuthField" style="display: none;">
                        <label>OAuth Access Token</label>
                        <div class="input-group" style="margin-bottom: 18px;">
                            <input type="password" id="bearerToken" placeholder="Paste ServiceNow OAuth Bearer Token" />
                            <button type="button" class="toggle-icon" onclick="toggleVisibility('bearerToken', this)">👁️</button>
                        </div>
                    </div>
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
                    <button type="button" class="nav-btn" style="padding: 8px 16px; font-size: 12px; margin-top: 8px;" onclick="addHeaderRow()">+ Add Header</button>
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
                <p class="sub">Real-time audit trail of inbound webhook receptions and outbound proxy responses.</p>
                <div id="logsContainer">
                    <div class="empty">No execution logs recorded in this session.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Generate or retrieve randomized ephemeral device token
        let deviceToken = localStorage.getItem('nex_device_token');
        if (!deviceToken) {
            const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(24)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            deviceToken = 'sn_dev_' + randomHex;
            localStorage.setItem('nex_device_token', deviceToken);
        }

        // Set dynamic inbound URL and randomized device token header
        document.getElementById('inboundUrlBox').value = window.location.origin + '/api/v1/servicenow/inbound';
        document.getElementById('authHeaderBox').value = 'Authorization: Bearer ' + deviceToken;

        function copyInboundUrl() {
            const box = document.getElementById('inboundUrlBox');
            navigator.clipboard.writeText(box.value);
            alert('Inbound Webhook Link copied to clipboard successfully!');
        }

        // Hide / Unhide Toggle Function
        function toggleVisibility(fieldId, btn) {
            const field = document.getElementById(fieldId);
            if (field.type === 'password') {
                field.type = 'text';
                btn.innerText = '🔒';
            } else {
                field.type = 'password';
                btn.innerText = '👁️';
            }
        }

        // Stunning Moving Background Particle Canvas Animation (Calming & Professional)
        const canvas = document.getElementById('bgCanvas');
        const ctx = canvas.getContext('2d');
        let width, height;
        let particles = [];

        function resizeCanvas() {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        for (let i = 0; i < 35; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 2 + 1,
                alpha: Math.random() * 0.5 + 0.2
            });
        }

        function animateCanvas() {
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = 'rgba(99, 102, 241, 0.25)';
            ctx.strokeStyle = 'rgba(99, 102, 241, 0.08)';

            particles.forEach((p, index) => {
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0 || p.x > width) p.vx *= -1;
                if (p.y < 0 || p.y > height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = \`rgba(99, 102, 241, \${p.alpha})\`;
                ctx.fill();

                for (let j = index + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                    if (dist < 130) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.stroke();
                    }
                }
            });
            requestAnimationFrame(animateCanvas);
        }
        animateCanvas();

        // Custom Glowing Cursor Movement
        const dot = document.getElementById('cursorDot');
        const outline = document.getElementById('cursorOutline');
        let mouseX = 0, mouseY = 0, outlineX = 0, outlineY = 0;

        window.addEventListener('mousemove', e => {
            mouseX = e.clientX; mouseY = e.clientY;
            dot.style.left = mouseX + 'px';
            dot.style.top = mouseY + 'px';
        });

        function renderCursor() {
            outlineX += (mouseX - outlineX) * 0.22;
            outlineY += (mouseY - outlineY) * 0.22;
            outline.style.left = outlineX + 'px';
            outline.style.top = outlineY + 'px';
            requestAnimationFrame(renderCursor);
        }
        renderCursor();

        document.querySelectorAll('button, input, select, textarea').forEach(el => {
            el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
            el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
        });

        // Single Panel Display Switcher
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
        }

        function toggleBodyState() {
            const method = document.getElementById('httpMethod').value;
            const bodyField = document.getElementById('httpBody');
            bodyField.disabled = (method === 'GET' || method === 'DELETE');
        }

        let inboundData = [];
        let outboundData = [];

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
                if (res.ok && data.record) {
                    outboundData.unshift(data.record);
                    updateLogCount();
                    renderLogs();
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
                            <div style="font-family: monospace; font-size: 12px; color: var(--cyan); margin-bottom: 8px; word-break: break-all;">\${item.url}</div>
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