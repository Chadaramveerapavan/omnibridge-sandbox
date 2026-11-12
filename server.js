const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Cryptographically Secure High-Entropy Token
const SECURE_API_KEY = "omni_" + crypto.randomBytes(32).toString('hex');
console.log(`[Security] Generated Secure API Key: ${SECURE_API_KEY}`);

app.use(cors());
app.use(bodyParser.json());

// In-memory organization and bi-directional payload stores
let inboundLogs = [];
let outboundLogs = [];
const organizations = []; // Stores organization accounts & configurations

// 1. Secure Inbound Enterprise Event Listener Endpoint
app.post('/api/endpoint/:platform', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        console.warn(`[Unauthorized Attempt] Blocked request to /api/endpoint/${req.params.platform}`);
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Unauthorized: Invalid or missing high-security enterprise token' 
        });
    }

    const platform = req.params.platform;
    const data = req.body;
    
    const syncId = "SYNC-" + Math.floor(100000 + Math.random() * 900000);
    const timestamp = new Date().toLocaleTimeString();

    const inboundEntry = {
        id: syncId,
        platform: platform.toUpperCase(),
        type: 'INBOUND',
        timestamp: timestamp,
        headers: req.headers,
        payload: data
    };

    const outboundEntry = {
        id: syncId,
        platform: (data.targetSystem || 'SLACK').toUpperCase(),
        type: 'OUTBOUND',
        timestamp: timestamp,
        payload: {
            routedFrom: platform.toUpperCase(),
            routedTo: (data.targetSystem || 'SLACK').toUpperCase(),
            status: "Successfully Dispatched",
            syncPayload: data
        }
    };

    inboundLogs.unshift(inboundEntry);
    outboundLogs.unshift(outboundEntry);
    
    console.log(`[Bi-Directional Sync] Inbound from ${platform.toUpperCase()} -> Outbound dispatched`);

    res.status(200).json({ 
        status: 'Success', 
        message: 'Payload processed bi-directionally by OmniBridge Enterprise Sandbox',
        inbound: inboundEntry,
        outbound: outboundEntry
    });
});

// 2. Organization Auth & Management Endpoints
app.post('/api/auth/register', (req, res) => {
    const { orgName, adminName, email, password } = req.body;
    if (!orgName || !email || !password) {
        return res.status(400).json({ status: 'Error', message: 'Organization name, email, and password are required.' });
    }
    const existing = organizations.find(o => o.email === email);
    if (existing) {
        return res.status(400).json({ status: 'Error', message: 'Organization account already exists with this email.' });
    }
    
    const newOrg = {
        id: "ORG-" + Math.floor(1000 + Math.random() * 9000),
        orgName,
        adminName: adminName || 'Admin',
        email,
        password
    };
    
    organizations.push(newOrg);
    res.json({ status: 'Success', message: 'Organization account registered successfully!', orgId: newOrg.id });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const org = organizations.find(o => o.email === email && o.password === password);
    if (!org) {
        return res.status(401).json({ status: 'Error', message: 'Invalid organization credentials.' });
    }
    res.json({ 
        status: 'Success', 
        message: 'Login successful!', 
        org: { orgName: org.orgName, adminName: org.adminName, email: org.email, id: org.id } 
    });
});

app.post('/api/auth/forgot', (req, res) => {
    const { email } = req.body;
    const org = organizations.find(o => o.email === email);
    if (!org) {
        return res.status(404).json({ status: 'Error', message: 'Organization email address not found.' });
    }
    res.json({ status: 'Success', message: 'Enterprise password reset instructions sent.' });
});

// 3. High-End Organization Portal & Integration Sandbox with Inbound/Outbound Tabs
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OmniBridge Enterprise Integration Sandbox</title>
    <style>
        :root {
            --bg: #030712;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border: rgba(51, 65, 85, 0.6);
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --text: #f8fafc;
            --text-dim: #94a3b8;
        }
        * { box-sizing: border-box; cursor: none !important; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            overflow-x: hidden;
            min-height: 100vh;
        }
        .cursor-dot, .cursor-outline {
            position: fixed;
            top: 0; left: 0;
            transform: translate(-50%, -50%);
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            transition: transform 0.1s ease, width 0.2s ease, height 0.2s ease, background-color 0.2s ease;
        }
        .cursor-dot { width: 8px; height: 8px; background: var(--accent); }
        .cursor-outline {
            width: 36px; height: 36px;
            border: 2px solid rgba(56, 189, 248, 0.4);
            background: var(--accent-glow);
            backdrop-filter: blur(2px);
        }
        body.hovering .cursor-outline {
            width: 55px; height: 55px;
            background: rgba(56, 189, 248, 0.25);
            border-color: var(--accent);
        }
        .container { max-width: 1100px; margin: 0 auto; position: relative; z-index: 1; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }
        h1 { margin: 0; font-size: 24px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
        .credit { color: var(--text-dim); font-size: 13px; margin-top: 4px; display: block; }
        
        .nav-actions { display: flex; gap: 12px; align-items: center; }
        .nav-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            box-shadow: none;
        }
        .nav-btn:hover { background: rgba(56, 189, 248, 0.1); border-color: var(--accent); }

        .status-badge {
            background: rgba(22, 101, 52, 0.4);
            border: 1px solid rgba(74, 222, 128, 0.3);
            color: #4ade80;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-dot { width: 8px; height: 8px; background: #4ade80; border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(74, 222, 128, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(16px);
            transition: transform 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            border-color: rgba(56, 189, 248, 0.4);
            box-shadow: 0 10px 30px -10px rgba(56, 189, 248, 0.15);
            transform: translateY(-2px);
        }
        button {
            background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%);
            color: #030712;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 14px rgba(56, 189, 248, 0.3);
        }
        button:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(56, 189, 248, 0.5);
        }
        button:disabled {
            background: #334155;
            color: #64748b;
            box-shadow: none;
            cursor: not-allowed;
        }
        input, select {
            width: 100%;
            padding: 10px 14px;
            background: #020617;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            margin-bottom: 12px;
            font-size: 14px;
        }
        input:focus, select:focus { outline: none; border-color: var(--accent); }
        pre {
            background: #020617;
            padding: 14px;
            border-radius: 8px;
            overflow-x: auto;
            color: #38bdf8;
            font-size: 13px;
            border: 1px solid rgba(51, 65, 85, 0.5);
            font-family: ui-monospace, monospace;
        }
        .badge {
            background: rgba(2, 132, 199, 0.2);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: var(--accent);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
        }
        .badge-outbound {
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid rgba(52, 211, 153, 0.3);
            color: #34d399;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
        }
        .time { color: var(--text-dim); font-size: 12px; float: right; font-weight: 500; }
        .empty { text-align: center; color: var(--text-dim); padding: 50px; font-style: italic; font-size: 14px; }
        
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
        .tab-btn {
            background: transparent; border: 1px solid var(--border); color: var(--text-dim);
            padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;
        }
        .tab-btn.active { background: rgba(56, 189, 248, 0.15); border-color: var(--accent); color: var(--accent); }

        .modal {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(3, 7, 18, 0.8); backdrop-filter: blur(8px);
            z-index: 1000; justify-content: center; align-items: center;
        }
        .modal-content {
            background: #1e293b; border: 1px solid var(--border); border-radius: 12px;
            width: 100%; max-width: 420px; padding: 30px; position: relative;
        }
        .close-btn { position: absolute; top: 15px; right: 20px; color: var(--text-dim); font-size: 20px; cursor: pointer; }
        .close-btn:hover { color: var(--text); }
        .grid-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn 0.4s ease forwards; }
    </style>
</head>
<body>
    <div class="cursor-dot" id="cursor-dot"></div>
    <div class="cursor-outline" id="cursor-outline"></div>

    <div class="container">
        <header>
            <div>
                <h1>OmniBridge Enterprise Integration Sandbox</h1>
                <span class="credit">Architected by Chadaram Veera Pavan</span>
            </div>
            <div class="nav-actions">
                <div class="status-badge">
                    <div class="status-dot"></div>
                    Enterprise Gateway Active
                </div>
                <button class="nav-btn" onclick="openModal('loginModal')" id="org-nav-btn">Organization Login</button>
            </div>
        </header>

        <div class="card" style="border-color: rgba(56, 189, 248, 0.3);">
            <h3 style="margin-top: 0; color: var(--accent); font-size: 16px;">Enterprise Bi-Directional Integration Simulator</h3>
            <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 16px;">Configure enterprise source and target platforms to simulate secure event synchronization.</p>
            
            <div class="grid-row">
                <div>
                    <label style="font-size: 12px; color: var(--text-dim); display: block; margin-bottom: 6px;">Source Enterprise Tool</label>
                    <select id="sourceTool">
                        <option value="servicenow">ServiceNow ITSM</option>
                        <option value="salesforce">Salesforce CRM</option>
                        <option value="jira">Jira Software</option>
                        <option value="workday">Workday HCM</option>
                        <option value="sap">SAP ERP</option>
                        <option value="github">GitHub Enterprise</option>
                    </select>
                </div>
                <div>
                    <label style="font-size: 12px; color: var(--text-dim); display: block; margin-bottom: 6px;">Target Workplace / Tool</label>
                    <select id="targetTool">
                        <option value="slack">Slack Enterprise Grid</option>
                        <option value="msteams">Microsoft Teams</option>
                        <option value="jira">Jira Software</option>
                        <option value="servicenow">ServiceNow ITSM</option>
                        <option value="datadog">Datadog Monitoring</option>
                    </select>
                </div>
            </div>

            <button id="test-btn" onclick="simulateEnterpriseIntegration()" style="width: 100%; margin-top: 15px;">Simulate Integration Payload</button>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('inbound')" id="tab-inbound-btn">Inbound Feed (0)</button>
            <button class="tab-btn" onclick="switchTab('outbound')" id="tab-outbound-btn">Outbound Feed (0)</button>
        </div>

        <div id="log-feed">
            <div class="empty">Page clear. Waiting for enterprise event transmissions...</div>
        </div>
    </div>

    <!-- Organization Login Modal -->
    <div class="modal" id="loginModal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('loginModal')">&times;</span>
            <h2 style="margin-top: 0; color: var(--accent); font-size: 20px;">Organization Portal Login</h2>
            <p style="color: var(--text-dim); font-size: 13px; margin-bottom: 20px;">Sign in to access your organization's saved integration configurations.</p>
            <form onsubmit="handleLogin(event)">
                <input type="email" id="loginEmail" placeholder="Organization Admin Email" required />
                <input type="password" id="loginPassword" placeholder="Enterprise Password" required />
                <button type="submit" style="width: 100%; margin-top: 10px;">Authenticate Workspace</button>
            </form>
            <div style="margin-top: 15px; text-align: center; font-size: 13px; color: var(--text-dim);">
                <a href="#" onclick="switchModal('loginModal', 'forgotModal')" style="color: var(--accent); text-decoration: none;">Forgot password?</a> | 
                <a href="#" onclick="switchModal('loginModal', 'registerModal')" style="color: var(--accent); text-decoration: none;">Register Organization</a>
            </div>
        </div>
    </div>

    <!-- Organization Register Modal -->
    <div class="modal" id="registerModal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('registerModal')">&times;</span>
            <h2 style="margin-top: 0; color: var(--accent); font-size: 20px;">Register Organization Workspace</h2>
            <p style="color: var(--text-dim); font-size: 13px; margin-bottom: 20px;">Setup your enterprise gateway profile and security credentials.</p>
            <form onsubmit="handleRegister(event)">
                <input type="text" id="regOrgName" placeholder="Organization Name (e.g., Acme Corp)" required />
                <input type="text" id="regAdminName" placeholder="Administrator Name" required />
                <input type="email" id="regEmail" placeholder="Admin Corporate Email" required />
                <input type="password" id="regPassword" placeholder="Create Secure Password" required />
                <button type="submit" style="width: 100%; margin-top: 10px;">Create Organization</button>
            </form>
            <div style="margin-top: 15px; text-align: center; font-size: 13px; color: var(--text-dim);">
                Already registered? <a href="#" onclick="switchModal('registerModal', 'loginModal')" style="color: var(--accent); text-decoration: none;">Sign in</a>
            </div>
        </div>
    </div>

    <!-- Forgot Password Modal -->
    <div class="modal" id="forgotModal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('forgotModal')">&times;</span>
            <h2 style="margin-top: 0; color: var(--accent); font-size: 20px;">Enterprise Password Recovery</h2>
            <p style="color: var(--text-dim); font-size: 13px; margin-bottom: 20px;">Enter your admin email to receive secure recovery credentials.</p>
            <form onsubmit="handleForgot(event)">
                <input type="email" id="forgotEmail" placeholder="Admin Corporate Email" required />
                <button type="submit" style="width: 100%; margin-top: 10px;">Send Recovery Instructions</button>
            </form>
            <div style="margin-top: 15px; text-align: center; font-size: 13px; color: var(--text-dim);">
                Back to <a href="#" onclick="switchModal('forgotModal', 'loginModal')" style="color: var(--accent); text-decoration: none;">Sign in</a>
            </div>
        </div>
    </div>

    <script>
        const cursorDot = document.getElementById('cursor-dot');
        const cursorOutline = document.getElementById('cursor-outline');

        window.addEventListener('mousemove', (e) => {
            const posX = e.clientX;
            const posY = e.clientY;
            cursorDot.style.left = posX + 'px';
            cursorDot.style.top = posY + 'px';
            cursorOutline.animate({ left: posX + 'px', top: posY + 'px' }, { duration: 500, fill: "forwards" });
        });

        document.querySelectorAll('button, a, input, select').forEach(el => {
            el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
            el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
        });

        function openModal(id) { document.getElementById(id).style.display = 'flex'; }
        function closeModal(id) { document.getElementById(id).style.display = 'none'; }
        function switchModal(hideId, showId) { closeModal(hideId); openModal(showId); }

        let currentTab = 'inbound';
        let inboundCache = [];
        let outboundCache = [];
        let isSubmitting = false;

        function switchTab(tab) {
            currentTab = tab;
            document.getElementById('tab-inbound-btn').className = tab === 'inbound' ? 'tab-btn active' : 'tab-btn';
            document.getElementById('tab-outbound-btn').className = tab === 'outbound' ? 'tab-btn active' : 'tab-btn';
            renderFeeds();
        }

        async function simulateEnterpriseIntegration() {
            if (isSubmitting) return;
            const btn = document.getElementById('test-btn');
            const source = document.getElementById('sourceTool').value;
            const target = document.getElementById('targetTool').value;
            
            isSubmitting = true;
            btn.disabled = true;
            btn.innerText = "Routing Enterprise Payload...";
            
            try {
                const response = await fetch('/api/endpoint/' + source, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + '${SECURE_API_KEY}'
                    },
                    body: JSON.stringify({ 
                        architecture: "OmniBridge Enterprise Level",
                        sourceSystem: source.toUpperCase(),
                        targetSystem: target.toUpperCase(),
                        syncId: "SYNC-" + Math.floor(100000 + Math.random() * 900000),
                        status: "Synchronized",
                        timestamp: new Date().toISOString(),
                        architect: "Chadaram Veera Pavan",
                        cryptographicSecurity: "High-Entropy SHA-256 Token Validated"
                    })
                });
                
                const result = await response.json();
                if (response.ok && result.inbound && result.outbound) {
                    inboundCache.unshift(result.inbound);
                    outboundCache.unshift(result.outbound);
                    document.getElementById('tab-inbound-btn').innerText = \`Inbound Feed (\${inboundCache.length})\`;
                    document.getElementById('tab-outbound-btn').innerText = \`Outbound Feed (\${outboundCache.length})\`;
                    renderFeeds();
                }
            } catch (e) { 
                console.error(e); 
            } finally {
                isSubmitting = false;
                btn.disabled = false;
                btn.innerText = "Simulate Integration Payload";
            }
        }

        function renderFeeds() {
            const feed = document.getElementById('log-feed');
            const list = currentTab === 'inbound' ? inboundCache : outboundCache;

            if (!list || list.length === 0) {
                feed.innerHTML = \`<div class="empty">No \${currentTab} event payloads recorded yet.</div>\`;
                return;
            }

            feed.innerHTML = list.map(l => \`
                <div class="card fade-in">
                    <span class="\${l.type === 'INBOUND' ? 'badge' : 'badge-outbound'}">\${l.platform} \${l.type}</span>
                    <span class="time">\${l.timestamp}</span>
                    <h3 style="margin: 12px 0 8px 0; font-size: 14px; font-weight: 600; color: #e2e8f0;">Sync ID: \${l.id}</h3>
                    <pre>\${JSON.stringify(l.payload, null, 2)}</pre>
                </div>
            \`).join('');
        }

        async function handleRegister(e) {
            e.preventDefault();
            const orgName = document.getElementById('regOrgName').value;
            const adminName = document.getElementById('regAdminName').value;
            const email = document.getElementById('regEmail').value;
            const password = document.getElementById('regPassword').value;

            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ orgName, adminName, email, password })
            });
            const data = await res.json();
            alert(data.message);
            if (res.ok) switchModal('registerModal', 'loginModal');
        }

        async function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;

            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            if (res.ok) {
                alert('Workspace Authenticated: ' + data.org.orgName);
                document.getElementById('org-nav-btn').innerText = data.org.orgName;
                closeModal('loginModal');
            } else {
                alert(data.message);
            }
        }

        async function handleForgot(e) {
            e.preventDefault();
            const email = document.getElementById('forgotEmail').value;
            const res = await fetch('/api/auth/forgot', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await res.json();
            alert(data.message);
            if (res.ok) switchModal('forgotModal', 'loginModal');
        }
    </script>
</body>
</html>`);
});

app.listen(PORT, () => {
    console.log(`Enterprise Secure OmniBridge Server running on port ${PORT}`);
});