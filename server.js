const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Cryptographically Secure High-Entropy Token
const SECURE_API_KEY = "nex_" + crypto.randomBytes(32).toString('hex');
console.log(`[Security] Generated NexRelay Secure API Key: ${SECURE_API_KEY}`);

app.use(cors());
app.use(bodyParser.json());

// In-memory stores (Cleared on server restart; frontend loads clean on page refresh)
let inboundLogs = [];
let outboundLogs = [];

const activeConnectors = [
    { id: 'c1', name: 'ServiceNow ITSM', category: 'ITSM', status: 'Active' },
    { id: 'c2', name: 'Salesforce CRM', category: 'CRM', status: 'Active' },
    { id: 'c3', name: 'Jira Software', category: 'Dev', status: 'Active' },
    { id: 'c4', name: 'Workday HCM', category: 'HRMS', status: 'Active' },
    { id: 'c5', name: 'Slack Enterprise', category: 'Communication', status: 'Active' },
    { id: 'c6', name: 'Custom REST API', category: 'Custom', status: 'Ready' }
];

// 1. Inbound Event Endpoint (External System -> NexRelay)
app.post('/api/v1/ingress/:connector', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        console.warn(`[Unauthorized] Blocked ingestion attempt for ${req.params.connector}`);
        return res.status(401).json({ status: 'Error', message: 'Unauthorized: Invalid or missing cryptographic token' });
    }

    const connector = req.params.connector;
    const payload = req.body;
    const syncId = "INB-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();

    const inboundEntry = {
        id: syncId,
        source: connector.toUpperCase(),
        type: 'INBOUND',
        timestamp: timestamp,
        payload: payload
    };

    inboundLogs.unshift(inboundEntry);
    console.log(`[Inbound Recorded] Source: ${connector.toUpperCase()} | ID: ${syncId}`);

    res.status(200).json({
        status: 'Success',
        message: 'Inbound record created in NexRelay',
        inbound: inboundEntry
    });
});

// 2. Outbound Dispatch Endpoint (NexRelay Form -> External Target System)
app.post('/api/v1/egress/dispatch', async (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        return res.status(401).json({ status: 'Error', message: 'Unauthorized: Invalid or missing cryptographic token' });
    }

    const { targetSystem, targetUrl, recordTitle, customPayload } = req.body;

    if (!targetSystem || !recordTitle) {
        return res.status(400).json({ status: 'Error', message: 'Target System and Record Title are required.' });
    }

    const syncId = "OUT-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();

    let parsedPayload = {};
    try {
        parsedPayload = customPayload ? JSON.parse(customPayload) : { title: recordTitle };
    } catch (e) {
        parsedPayload = { title: recordTitle, rawNote: customPayload };
    }

    const dispatchEnvelope = {
        relayTransactionId: syncId,
        destinationSystem: targetSystem.toUpperCase(),
        destinationEndpoint: targetUrl || `https://api.${targetSystem.toLowerCase()}.com/v2/records`,
        recordTitle: recordTitle,
        createdInRemoteSystem: true,
        remoteRecordId: "EXT-" + Math.floor(10000 + Math.random() * 90000),
        data: parsedPayload,
        dispatchedAt: new Date().toISOString()
    };

    // If a live external URL is provided, attempt real HTTP POST delivery
    let deliveryStatus = 'Created in Target System (Simulated)';
    if (targetUrl && targetUrl.startsWith('http')) {
        try {
            const extRes = await fetch(targetUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(dispatchEnvelope)
            });
            deliveryStatus = extRes.ok ? `Created in Target System (HTTP ${extRes.status})` : `Target Returned HTTP ${extRes.status}`;
        } catch (err) {
            deliveryStatus = `Dispatched (Remote Endpoint Unreachable: ${err.message})`;
        }
    }

    const outboundEntry = {
        id: syncId,
        destination: targetSystem.toUpperCase(),
        type: 'OUTBOUND',
        status: deliveryStatus,
        timestamp: timestamp,
        payload: dispatchEnvelope
    };

    outboundLogs.unshift(outboundEntry);
    console.log(`[Outbound Dispatched] Target: ${targetSystem.toUpperCase()} | ID: ${syncId}`);

    res.status(200).json({
        status: 'Success',
        message: 'Record created in target system',
        outbound: outboundEntry
    });
});

app.get('/api/v1/connectors', (req, res) => res.json(activeConnectors));

// 3. NexRelay Open Enterprise SaaS Dashboard Frontend
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NexRelay | Enterprise Integration & Automation Platform</title>
    <style>
        :root {
            --bg: #090d16;
            --surface: #111827;
            --surface-glass: rgba(17, 24, 39, 0.78);
            --border: rgba(31, 41, 55, 0.9);
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.2);
            --success: #10b981;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            min-height: 100vh;
        }
        .container { max-width: 1180px; margin: 0 auto; }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 18px;
            margin-bottom: 24px;
        }
        .logo-area h1 { margin: 0; font-size: 24px; font-weight: 700; color: #fff; letter-spacing: -0.5px; display: flex; align-items: center; gap: 8px; }
        .logo-area h1 span { color: var(--accent); }
        .tagline { color: var(--text-dim); font-size: 12px; margin-top: 4px; display: block; }

        .status-pill {
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.35);
            color: var(--success);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .pulse-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* Connected Intelligence Flow Visualizer */
        .network-canvas {
            background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            height: 120px;
            display: flex;
            align-items: center;
            justify-content: space-around;
            padding: 0 40px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }
        .node {
            background: #1e293b;
            border: 1px solid var(--accent);
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            z-index: 2;
        }
        .core-engine {
            background: linear-gradient(135deg, var(--accent), #1d4ed8);
            color: #fff;
            padding: 12px 24px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 700;
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.35);
            z-index: 2;
        }
        .particle {
            position: absolute;
            width: 7px; height: 7px;
            background: #60a5fa;
            border-radius: 50%;
            box-shadow: 0 0 10px #60a5fa;
            animation: travel 3.5s infinite linear;
        }
        @keyframes travel {
            0% { left: 16%; opacity: 0; }
            50% { opacity: 1; }
            100% { left: 84%; opacity: 0; }
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .metric-card {
            background: var(--surface-glass);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
        }
        .metric-title { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
        .metric-value { font-size: 22px; font-weight: 700; color: #fff; margin-top: 6px; }

        .workspace-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 28px;
        }
        .card {
            background: var(--surface-glass);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }
        .card h3 { margin-top: 0; font-size: 15px; color: #fff; margin-bottom: 6px; }
        .card p { font-size: 12px; color: var(--text-dim); margin-top: 0; margin-bottom: 16px; }

        label { font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 5px; font-weight: 600; }
        input, select, textarea {
            width: 100%; padding: 10px 12px; background: #0b0f19;
            border: 1px solid var(--border); border-radius: 6px; color: var(--text);
            margin-bottom: 12px; font-size: 13px; font-family: inherit;
        }
        textarea { font-family: ui-monospace, monospace; font-size: 12px; resize: vertical; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); }

        button.primary {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: #fff; border: none; padding: 11px 18px; border-radius: 6px;
            font-weight: 600; font-size: 13px; cursor: pointer; width: 100%;
            box-shadow: 0 4px 12px var(--accent-glow);
            transition: all 0.2s ease;
        }
        button.primary:hover:not(:disabled) { transform: translateY(-1px); }
        button.primary:disabled {
            background: #1f2937;
            color: #6b7280;
            box-shadow: none;
            cursor: not-allowed;
        }

        button.outbound-btn {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: #fff; border: none; padding: 11px 18px; border-radius: 6px;
            font-weight: 600; font-size: 13px; cursor: pointer; width: 100%;
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.2);
            transition: all 0.2s ease;
        }
        button.outbound-btn:hover:not(:disabled) { transform: translateY(-1px); }

        .tabs { display: flex; gap: 8px; margin-bottom: 18px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }
        .tab-btn {
            background: transparent; border: 1px solid var(--border); color: var(--text-dim);
            padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;
        }
        .tab-btn.active { background: rgba(59, 130, 246, 0.15); border-color: var(--accent); color: var(--accent); }

        pre { background: #0b0f19; padding: 12px; border-radius: 6px; color: #60a5fa; font-size: 12px; overflow-x: auto; border: 1px solid var(--border); margin-bottom: 0; }
        .badge { background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); color: var(--accent); padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .badge-out { background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); color: var(--success); padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .time { color: var(--text-dim); font-size: 11px; float: right; }
        .empty { text-align: center; color: var(--text-dim); padding: 40px; font-style: italic; font-size: 13px; background: var(--surface-glass); border: 1px solid var(--border); border-radius: 10px; }
        @media (max-width: 850px) {
            .workspace-grid, .metrics-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>Nex<span>Relay</span></h1>
                <span class="tagline">Enterprise Integration & Automation Platform · Connect. Transform. Route. Monitor.</span>
            </div>
            <div class="status-pill">
                <div class="pulse-dot"></div>
                Open Integration Hub Active
            </div>
        </header>

        <!-- Connected Intelligence Flow Visualizer -->
        <div class="network-canvas">
            <div class="particle" style="top: 50%;"></div>
            <div class="node">Inbound Source Systems</div>
            <div class="core-engine">NexRelay Core Engine</div>
            <div class="node">Outbound Target Systems</div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Available Connectors</div>
                <div class="metric-value">6</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Inbound Records</div>
                <div class="metric-value" id="m-inbound">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Outbound Records</div>
                <div class="metric-value" id="m-outbound">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Delivery Health</div>
                <div class="metric-value" style="color: var(--success);">100%</div>
            </div>
        </div>

        <!-- Dual Workspace: Inbound Simulator & Outbound Creation Form -->
        <div class="workspace-grid">
            <!-- Left: Inbound Event Trigger (Single-Trigger Locked) -->
            <div class="card">
                <h3>1. Inbound Ingestion (External &rarr; NexRelay)</h3>
                <p>Simulate an incoming payload from a source platform. Creates a single record in the <strong>Inbound Ingress</strong> tab.</p>
                
                <label>Source Enterprise Platform</label>
                <select id="inboundSource">
                    <option value="servicenow">ServiceNow ITSM</option>
                    <option value="salesforce">Salesforce CRM</option>
                    <option value="jira">Jira Software</option>
                    <option value="workday">Workday HCM</option>
                    <option value="sap">SAP ERP</option>
                    <option value="github">GitHub Enterprise</option>
                </select>

                <label>Inbound Event Type</label>
                <select id="inboundEventType">
                    <option value="incident.created">incident.created</option>
                    <option value="account.updated">account.updated</option>
                    <option value="issue.resolved">issue.resolved</option>
                    <option value="employee.onboarded">employee.onboarded</option>
                </select>

                <button class="primary" id="inbound-btn" onclick="triggerInboundOnce()">Send Inbound Payload (Single Event)</button>
            </div>

            <!-- Right: Outbound Record Creation Form (NexRelay -> Other System) -->
            <div class="card">
                <h3>2. Outbound Dispatch Form (NexRelay &rarr; Other System)</h3>
                <p>Fill out this form to create and push a new record directly into an external target system.</p>
                
                <form id="outboundForm" onsubmit="submitOutboundForm(event)">
                    <label>Target Destination System</label>
                    <select id="outTargetSystem" required>
                        <option value="ServiceNow">ServiceNow ITSM</option>
                        <option value="Jira">Jira Software</option>
                        <option value="Salesforce">Salesforce CRM</option>
                        <option value="Slack">Slack Enterprise Grid</option>
                        <option value="Microsoft Teams">Microsoft Teams</option>
                        <option value="Custom REST API">Custom REST API</option>
                    </select>

                    <label>Record Title / Summary</label>
                    <input type="text" id="outRecordTitle" placeholder="e.g., Provision New VPN Access for Engineering" required />

                    <label>Target Endpoint URL (Optional - leaves blank for sandbox target)</label>
                    <input type="url" id="outTargetUrl" placeholder="https://your-instance.service-now.com/api/now/table/incident" />

                    <label>Record Payload Data (JSON)</label>
                    <textarea id="outPayload" rows="2">{"priority": "High", "category": "Infrastructure", "requestedBy": "NexRelay"}</textarea>

                    <button type="submit" class="outbound-btn" id="outbound-btn">Create Record in Target System</button>
                </form>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('inbound')" id="btn-inbound">Inbound Ingress (0)</button>
            <button class="tab-btn" onclick="switchTab('outbound')" id="btn-outbound">Outbound Delivery (0)</button>
            <button class="tab-btn" onclick="switchTab('connectors')" id="btn-connectors">Active Connectors (6)</button>
        </div>

        <div id="feed-container">
            <div class="empty">Page clear. Trigger an inbound event or submit the outbound form above.</div>
        </div>
    </div>

    <script>
        let currentTab = 'inbound';
        let inboundCache = [];
        let outboundCache = [];
        let connectorsCache = [];
        let hasTriggeredInbound = false;
        let isSubmittingOutbound = false;

        function switchTab(tab) {
            currentTab = tab;
            ['inbound', 'outbound', 'connectors'].forEach(t => {
                document.getElementById('btn-' + t).className = t === tab ? 'tab-btn active' : 'tab-btn';
            });
            renderData();
        }

        function updateCounters() {
            document.getElementById('m-inbound').innerText = inboundCache.length;
            document.getElementById('m-outbound').innerText = outboundCache.length;
            document.getElementById('btn-inbound').innerText = \`Inbound Ingress (\${inboundCache.length})\`;
            document.getElementById('btn-outbound').innerText = \`Outbound Delivery (\${outboundCache.length})\`;
        }

        // Strict single-execution inbound trigger (prevents any duplicate payloads)
        async function triggerInboundOnce() {
            if (hasTriggeredInbound) return;
            hasTriggeredInbound = true;

            const btn = document.getElementById('inbound-btn');
            btn.disabled = true;
            btn.innerText = "Inbound Payload Sent (1/1)";

            const source = document.getElementById('inboundSource').value;
            const eventType = document.getElementById('inboundEventType').value;

            try {
                const res = await fetch('/api/v1/ingress/' + source, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + '${SECURE_API_KEY}'
                    },
                    body: JSON.stringify({
                        eventType: eventType,
                        sourceSystem: source.toUpperCase(),
                        recordId: 'REC-' + Math.floor(10000 + Math.random() * 90000),
                        status: 'Received by NexRelay',
                        timestamp: new Date().toISOString()
                    })
                });
                const data = await res.json();
                if (res.ok && data.inbound) {
                    inboundCache.unshift(data.inbound);
                    updateCounters();
                    switchTab('inbound');
                }
            } catch (e) {
                console.error(e);
            }
        }

        // Outbound Form Submission -> Creates record in target system & logs in Outbound tab
        async function submitOutboundForm(e) {
            e.preventDefault();
            if (isSubmittingOutbound) return;

            const btn = document.getElementById('outbound-btn');
            isSubmittingOutbound = true;
            btn.disabled = true;
            btn.innerText = "Creating Record in Target System...";

            const targetSystem = document.getElementById('outTargetSystem').value;
            const recordTitle = document.getElementById('outRecordTitle').value;
            const targetUrl = document.getElementById('outTargetUrl').value;
            const customPayload = document.getElementById('outPayload').value;

            try {
                const res = await fetch('/api/v1/egress/dispatch', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + '${SECURE_API_KEY}'
                    },
                    body: JSON.stringify({
                        targetSystem,
                        recordTitle,
                        targetUrl,
                        customPayload
                    })
                });
                const data = await res.json();
                if (res.ok && data.outbound) {
                    outboundCache.unshift(data.outbound);
                    updateCounters();
                    switchTab('outbound');
                    document.getElementById('outRecordTitle').value = '';
                } else {
                    alert(data.message || 'Failed to dispatch outbound record');
                }
            } catch (err) {
                console.error(err);
            } finally {
                isSubmittingOutbound = false;
                btn.disabled = false;
                btn.innerText = "Create Record in Target System";
            }
        }

        async function loadConnectors() {
            try {
                const res = await fetch('/api/v1/connectors');
                connectorsCache = await res.json();
            } catch(e) { console.error(e); }
        }

        function renderData() {
            const container = document.getElementById('feed-container');
            if (currentTab === 'connectors') {
                container.innerHTML = connectorsCache.map(c => \`
                    <div class="card">
                        <span class="badge">\${c.category}</span>
                        <h3 style="margin: 8px 0 4px 0; font-size: 14px; color:#fff;">\${c.name}</h3>
                        <p style="margin:0; font-size:12px; color: var(--success);">● Status: \${c.status}</p>
                    </div>
                \`).join('');
                return;
            }

            const list = currentTab === 'inbound' ? inboundCache : outboundCache;
            if (!list || list.length === 0) {
                container.innerHTML = \`<div class="empty">No \${currentTab} records yet.</div>\`;
                return;
            }

            container.innerHTML = list.map(l => \`
                <div class="card">
                    <span class="\${l.type === 'INBOUND' ? 'badge' : 'badge-out'}">\${l.source || l.destination} · \${l.type}</span>
                    <span class="time">\${l.timestamp}</span>
                    <h3 style="margin: 10px 0 6px 0; font-size: 13px; color: #fff;">
                        Transaction ID: \${l.id} \${l.status ? '— <span style="color: var(--success);">' + l.status + '</span>' : ''}
                    </h3>
                    <pre>\${JSON.stringify(l.payload, null, 2)}</pre>
                </div>
            \`).join('');
        }

        loadConnectors();
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`NexRelay Open Enterprise Integration Platform running on port ${PORT}`);
});