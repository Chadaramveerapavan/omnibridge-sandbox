const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const INBOUND_TOKEN = process.env.INBOUND_TOKEN;

app.use(express.json({ limit: '1mb' }));

// ---------------- DATABASE ----------------

let database = {
    inbound: [],
    outbound: []
};

let saveQueue = Promise.resolve();

async function loadDatabase() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            await fs.promises.writeFile(
                DB_FILE,
                JSON.stringify(database, null, 2)
            );
            return;
        }

        const data = await fs.promises.readFile(DB_FILE, 'utf8');
        const parsed = JSON.parse(data);

        database = {
            inbound: Array.isArray(parsed.inbound) ? parsed.inbound : [],
            outbound: Array.isArray(parsed.outbound) ? parsed.outbound : []
        };
    } catch (error) {
        console.error('Database loading error:', error.message);
        throw error;
    }
}

function saveDatabase() {
    saveQueue = saveQueue.then(async () => {
        const tempFile = DB_FILE + '.tmp';

        await fs.promises.writeFile(
            tempFile,
            JSON.stringify(database, null, 2),
            'utf8'
        );

        await fs.promises.rename(tempFile, DB_FILE);
    });

    return saveQueue;
}

// ---------------- HELPERS ----------------

function safeTokenCompare(received, expected) {
    if (!received || !expected) return false;

    const a = Buffer.from(received);
    const b = Buffer.from(expected);

    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createId(prefix) {
    return prefix + '-' + crypto.randomUUID();
}

function createTimestamp() {
    return new Date().toISOString();
}

function validateServiceNowUrl(value) {
    try {
        const url = new URL(value);

        if (url.protocol !== 'https:') return false;

        const hostname = url.hostname.toLowerCase();

        if (
            hostname === 'service-now.com' ||
            !hostname.endsWith('.service-now.com')
        ) {
            return false;
        }

        if (url.username || url.password) return false;

        return true;
    } catch {
        return false;
    }
}

// ---------------- INBOUND INTEGRATION ----------------

app.post('/api/v1/servicenow/inbound', async (req, res) => {
    try {
        const authorization = req.headers.authorization || '';
        const receivedToken = authorization.startsWith('Bearer ')
            ? authorization.slice(7)
            : '';

        if (!safeTokenCompare(receivedToken, INBOUND_TOKEN)) {
            return res.status(401).json({
                status: 'Error',
                message: 'Invalid or missing inbound token.'
            });
        }

        const record = {
            id: createId('SN-INB'),
            direction: 'INBOUND',
            timestamp: createTimestamp(),
            status: 'Success',
            headers: {
                contentType: req.headers['content-type'] || ''
            },
            payload: req.body
        };

        database.inbound.unshift(record);
        await saveDatabase();

        console.log('Inbound record received:', record.id);

        res.status(201).json({
            status: 'Success',
            message: 'Inbound record saved successfully.',
            record
        });
    } catch (error) {
        console.error('Inbound error:', error.message);

        res.status(500).json({
            status: 'Error',
            message: 'Unable to save inbound record.'
        });
    }
});

// ---------------- OUTBOUND SERVICE NOW INTEGRATION ----------------

app.post('/api/v1/servicenow/outbound', async (req, res) => {
    const {
        method,
        url,
        authType,
        basicUser,
        basicPass,
        bearerToken,
        headers,
        body
    } = req.body;

    const httpMethod = String(method || '').toUpperCase();

    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(httpMethod)) {
        return res.status(400).json({
            status: 'Error',
            message: 'Unsupported HTTP method.'
        });
    }

    if (!url || !validateServiceNowUrl(url)) {
        return res.status(400).json({
            status: 'Error',
            message: 'Enter a valid HTTPS ServiceNow instance URL.'
        });
    }

    if (
        authType === 'basic' &&
        (!basicUser || !basicPass)
    ) {
        return res.status(400).json({
            status: 'Error',
            message: 'Basic authentication requires a username and password.'
        });
    }

    if (authType === 'bearer' && !bearerToken) {
        return res.status(400).json({
            status: 'Error',
            message: 'OAuth Bearer token is required.'
        });
    }

    if (!['basic', 'bearer', 'none'].includes(authType)) {
        return res.status(400).json({
            status: 'Error',
            message: 'Invalid authentication type.'
        });
    }

    const record = {
        id: createId('SN-OUT'),
        direction: 'OUTBOUND',
        method: httpMethod,
        url,
        timestamp: createTimestamp(),
        status: 'Failed',
        statusCode: null,
        durationMs: 0,
        requestPayload: body || null,
        responsePayload: null,
        diagnosticError: null
    };

    const startTime = Date.now();

    try {
        const requestHeaders = {
            Accept: 'application/json',
            'Content-Type': 'application/json'
        };

        // Accept only ordinary custom headers.
        if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
            for (const [key, value] of Object.entries(headers)) {
                const lowerKey = key.toLowerCase();

                if (
                    !/^[a-z0-9-]+$/i.test(key) ||
                    ['authorization', 'host', 'content-length',
                     'connection', 'cookie', 'transfer-encoding'].includes(lowerKey)
                ) {
                    continue;
                }

                if (typeof value === 'string') {
                    requestHeaders[key] = value;
                }
            }
        }

        if (authType === 'basic') {
            const credentials = Buffer
                .from(`${basicUser}:${basicPass}`)
                .toString('base64');

            requestHeaders.Authorization = `Basic ${credentials}`;
        }

        if (authType === 'bearer') {
            requestHeaders.Authorization = `Bearer ${bearerToken}`;
        }

        const fetchOptions = {
            method: httpMethod,
            headers: requestHeaders,
            redirect: 'manual',
            signal: AbortSignal.timeout(20000)
        };

        if (['POST', 'PUT', 'PATCH'].includes(httpMethod)) {
            if (body !== undefined && body !== null) {
                fetchOptions.body = typeof body === 'string'
                    ? body
                    : JSON.stringify(body);
            }
        }

        const response = await fetch(url, fetchOptions);

        record.statusCode = response.status;
        record.durationMs = Date.now() - startTime;

        const responseText = await response.text();

        if (responseText.length > 1024 * 1024) {
            throw new Error('ServiceNow response exceeded the 1 MB limit.');
        }

        try {
            record.responsePayload = responseText
                ? JSON.parse(responseText)
                : null;
        } catch {
            record.responsePayload = responseText;
        }

        record.status = response.ok ? 'Success' : 'Failed';

        if (!response.ok) {
            record.diagnosticError =
                `ServiceNow returned HTTP ${response.status}.`;
        }

    } catch (error) {
        record.status = 'Failed';
        record.durationMs = Date.now() - startTime;
        record.diagnosticError = error.name === 'TimeoutError'
            ? 'ServiceNow request timed out.'
            : error.message;

        record.responsePayload = {
            error: record.diagnosticError
        };
    }

    try {
        database.outbound.unshift(record);
        await saveDatabase();
    } catch (error) {
        console.error('Outbound history save error:', error.message);

        return res.status(500).json({
            status: 'Error',
            message: 'Request completed, but execution history could not be saved.',
            record
        });
    }

    console.log(
        `[Outbound] ${httpMethod} -> ${record.statusCode || 'Network Error'}`
    );

    res.status(record.status === 'Success' ? 200 : 502).json({
        status: record.status,
        record
    });
});

// ---------------- GET EXECUTION LOGS ----------------

app.get('/api/v1/servicenow/logs', (req, res) => {
    res.json({
        inbound: database.inbound,
        outbound: database.outbound
    });
});

// ---------------- DELETE INDIVIDUAL RECORD ----------------

app.delete('/api/v1/servicenow/logs/:direction/:id', async (req, res) => {
    try {
        const direction = req.params.direction;
        const id = req.params.id;

        let collection;

        if (direction === 'inbound') {
            collection = database.inbound;
        } else if (direction === 'outbound') {
            collection = database.outbound;
        } else {
            return res.status(400).json({
                status: 'Error',
                message: 'Invalid record direction.'
            });
        }

        const index = collection.findIndex(item => item.id === id);

        if (index === -1) {
            return res.status(404).json({
                status: 'Error',
                message: 'Record not found.'
            });
        }

        collection.splice(index, 1);
        await saveDatabase();

        res.json({
            status: 'Success',
            message: 'Record deleted successfully.'
        });
    } catch (error) {
        console.error('Delete error:', error.message);

        res.status(500).json({
            status: 'Error',
            message: 'Unable to delete record.'
        });
    }
});

// ---------------- DASHBOARD ----------------

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NexRelay | ServiceNow Integration Hub</title>
<style>
:root {
    --bg:#030409;
    --card:#101628;
    --border:rgba(99,102,241,.3);
    --indigo:#6366f1;
    --cyan:#38bdf8;
    --green:#10b981;
    --red:#f43f5e;
    --text:#f8fafc;
    --muted:#94a3b8;
}
* { box-sizing:border-box; }
body {
    margin:0;
    padding:30px 20px;
    min-height:100vh;
    background:var(--bg);
    color:var(--text);
    font-family:Segoe UI,Arial,sans-serif;
}
.container { max-width:1150px;margin:auto; }
header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    flex-wrap:wrap;
    gap:15px;
    border-bottom:1px solid var(--border);
    padding-bottom:22px;
}
h1 { font-size:25px;margin:0; }
h1 span { color:var(--indigo); }
.subtitle { color:var(--muted);font-size:13px; }
.status {
    color:var(--cyan);
    border:1px solid var(--border);
    padding:9px 15px;
    border-radius:20px;
    font-size:12px;
}
.tabs { display:flex;gap:10px;margin:25px 0;flex-wrap:wrap; }
button {
    cursor:pointer;
    border:1px solid var(--border);
    border-radius:8px;
    padding:11px 17px;
    background:#11182b;
    color:var(--text);
}
button:hover { border-color:var(--cyan); }
.tab.active,.primary {
    background:var(--indigo);
    border-color:var(--indigo);
    color:white;
}
.panel { display:none; }
.panel.active { display:block; }
.card {
    background:var(--card);
    border:1px solid var(--border);
    border-radius:14px;
    padding:25px;
    margin-bottom:20px;
}
h2 { font-size:18px;margin-top:0; }
label {
    display:block;
    color:var(--muted);
    font-size:11px;
    font-weight:bold;
    margin:15px 0 7px;
    text-transform:uppercase;
}
input,select,textarea {
    width:100%;
    background:var(--bg);
    border:1px solid var(--border);
    color:var(--text);
    border-radius:8px;
    padding:12px;
    margin-bottom:10px;
}
textarea { min-height:150px;font-family:monospace; }
.row { display:grid;grid-template-columns:1fr 1fr;gap:15px; }
.full { width:100%;margin-top:12px; }
.log {
    background:#080d19;
    border:1px solid var(--border);
    border-radius:10px;
    padding:18px;
    margin:14px 0;
    overflow-wrap:anywhere;
}
.log-top {
    display:flex;
    justify-content:space-between;
    gap:10px;
    flex-wrap:wrap;
    align-items:center;
}
.badge {
    display:inline-block;
    padding:5px 9px;
    border-radius:5px;
    background:#252b48;
    font-size:11px;
}
.success { color:#34d399; }
.failure { color:#fb7185; }
pre {
    white-space:pre-wrap;
    overflow-wrap:anywhere;
    background:#030409;
    border-radius:7px;
    padding:12px;
    color:#cbd5e1;
    font-size:12px;
}
.delete {
    background:#451522;
    border-color:#9f1239;
    color:#fda4af;
}
.empty {
    text-align:center;
    padding:35px;
    color:var(--muted);
}
.note { color:var(--muted);font-size:12px;line-height:1.6; }
@media(max-width:650px) {
    body { padding:18px 12px; }
    .row { grid-template-columns:1fr;gap:0; }
    .card { padding:17px; }
}
</style>
</head>
<body>
<div class="container">

<header>
    <div>
        <h1>Nex<span>Relay</span> · ServiceNow Integration Hub</h1>
        <div class="subtitle">Connect. Transform. Route. Monitor.</div>
    </div>
    <div class="status">● Integration Hub</div>
</header>

<div class="tabs">
    <button class="tab active" onclick="showPanel('inbound',this)">Inbound Integration</button>
    <button class="tab" onclick="showPanel('outbound',this)">Create ServiceNow Record</button>
    <button class="tab" onclick="showPanel('logs',this)">Execution History (<span id="count">0</span>)</button>
</div>

<section id="inbound" class="panel active">
    <div class="card">
        <h2>Inbound Integration Endpoint</h2>
        <p class="note">Configure this endpoint in ServiceNow when sending data to NexRelay.</p>

        <label>NexRelay Inbound URL</label>
        <input id="inboundUrl" readonly>

        <button onclick="copyInboundUrl()">Copy URL</button>

        <p class="note">
            Authorization header: Bearer YOUR_INBOUND_TOKEN.
            Configure the same token in your server environment as INBOUND_TOKEN.
        </p>
    </div>
</section>

<section id="outbound" class="panel">
    <div class="card">
        <h2>Create or Manage a ServiceNow Record</h2>
        <p class="note">Send a request to your ServiceNow Table API. The result will be saved in NexRelay history.</p>

        <label>HTTP Method</label>
        <select id="method" onchange="toggleBody()">
            <option>POST</option>
            <option>GET</option>
            <option>PUT</option>
            <option>PATCH</option>
            <option>DELETE</option>
        </select>

        <label>ServiceNow API URL</label>
        <input id="url" type="url" placeholder="https://dev12345.service-now.com/api/now/table/incident">

        <label>Authentication Type</label>
        <select id="authType" onchange="toggleAuth()">
            <option value="basic">Basic Authentication</option>
            <option value="bearer">OAuth 2.0 Bearer Token</option>
            <option value="none">No Authentication</option>
        </select>

        <div id="basicFields">
            <div class="row">
                <div>
                    <label>Username</label>
                    <input id="username" autocomplete="off">
                </div>
                <div>
                    <label>Password</label>
                    <input id="password" type="password" autocomplete="off">
                </div>
            </div>
        </div>

        <div id="bearerFields" style="display:none">
            <label>OAuth Access Token</label>
            <input id="token" type="password" autocomplete="off">
        </div>

        <label>Request Body (JSON)</label>
        <textarea id="body">{
  "short_description": "Incident created using NexRelay",
  "description": "Testing ServiceNow integration",
  "urgency": "2",
  "impact": "2"
}</textarea>

        <button class="primary full" id="sendButton" onclick="sendRequest()">Send Request to ServiceNow</button>
        <p class="note">For incident creation, use POST and the incident Table API endpoint. The ServiceNow account must have permission to create records in the selected table.</p>
    </div>
</section>

<section id="logs" class="panel">
    <div class="card">
        <h2>Execution History</h2>
        <p class="note">Inbound and outbound records are stored in database.json. Delete buttons remove individual records from that file.</p>
        <button onclick="loadLogs()">Refresh History</button>
        <div id="logsContainer"></div>
    </div>
</section>

</div>

<script>
document.getElementById('inboundUrl').value =
    location.origin + '/api/v1/servicenow/inbound';

function showPanel(id,button) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    button.classList.add('active');

    if (id === 'logs') loadLogs();
}

function copyInboundUrl() {
    navigator.clipboard.writeText(document.getElementById('inboundUrl').value)
        .then(() => alert('Inbound URL copied.'));
}

function toggleAuth() {
    const type = document.getElementById('authType').value;
    document.getElementById('basicFields').style.display =
        type === 'basic' ? 'block' : 'none';
    document.getElementById('bearerFields').style.display =
        type === 'bearer' ? 'block' : 'none';
}

function toggleBody() {
    const method = document.getElementById('method').value;
    document.getElementById('body').disabled =
        method === 'GET' || method === 'DELETE';
}

async function sendRequest() {
    const button = document.getElementById('sendButton');
    const method = document.getElementById('method').value;
    const url = document.getElementById('url').value.trim();
    const authType = document.getElementById('authType').value;

    if (!url) {
        alert('Enter the ServiceNow API URL.');
        return;
    }

    let body = null;

    if (['POST','PUT','PATCH'].includes(method)) {
        try {
            body = JSON.parse(document.getElementById('body').value);
        } catch {
            alert('Request body must contain valid JSON.');
            return;
        }
    }

    const request = {
        method,
        url,
        authType,
        basicUser: document.getElementById('username').value,
        basicPass: document.getElementById('password').value,
        bearerToken: document.getElementById('token').value,
        body
    };

    button.disabled = true;
    button.textContent = 'Sending request...';

    try {
        const response = await fetch('/api/v1/servicenow/outbound', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(request)
        });

        const result = await response.json();

        if (result.record) {
            alert(
                result.status + '\\n' +
                'HTTP Status: ' + (result.record.statusCode || 'No response') +
                (result.record.diagnosticError
                    ? '\\n' + result.record.diagnosticError : '')
            );
        } else {
            alert(result.message || 'Request failed.');
        }

        await loadLogs();

    } catch (error) {
        alert('Unable to contact NexRelay server: ' + error.message);
    } finally {
        button.disabled = false;
        button.textContent = 'Send Request to ServiceNow';
    }
}

function addText(parent,tag,value,className) {
    const element = document.createElement(tag);
    element.textContent = value == null ? '' :
        typeof value === 'string' ? value : JSON.stringify(value,null,2);

    if (className) element.className = className;
    parent.appendChild(element);
    return element;
}

async function deleteRecord(direction,id) {
    if (!confirm('Delete this execution record permanently?')) return;

    try {
        const response = await fetch(
            '/api/v1/servicenow/logs/' + direction + '/' + encodeURIComponent(id),
            {method:'DELETE'}
        );

        const result = await response.json();

        if (!response.ok) {
            alert(result.message || 'Unable to delete record.');
            return;
        }

        await loadLogs();
    } catch (error) {
        alert('Delete failed: ' + error.message);
    }
}

async function loadLogs() {
    const container = document.getElementById('logsContainer');
    container.textContent = 'Loading records...';

    try {
        const response = await fetch('/api/v1/servicenow/logs');
        const data = await response.json();

        const allLogs = [
            ...data.inbound.map(item => ({...item, collection:'inbound'})),
            ...data.outbound.map(item => ({...item, collection:'outbound'}))
        ].sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));

        document.getElementById('count').textContent = allLogs.length;
        container.replaceChildren();

        if (!allLogs.length) {
            addText(container,'div','No execution records available.','empty');
            return;
        }

        allLogs.forEach(item => {
            const card = document.createElement('div');
            card.className = 'log';

            const top = document.createElement('div');
            top.className = 'log-top';

            const info = document.createElement('div');

            addText(info,'span',item.direction,'badge');
            addText(info,'span',
                ' ' + (item.method || '') + ' ' + item.id);

            const statusClass =
                item.status === 'Success' ||
                (item.statusCode >= 200 && item.statusCode < 300)
                ? 'success' : 'failure';

            addText(info,'span',
                '  ' + (item.status || 'Unknown') +
                (item.statusCode ? ' (' + item.statusCode + ')' : ''),
                statusClass);

            top.appendChild(info);

            const deleteButton = document.createElement('button');
            deleteButton.className = 'delete';
            deleteButton.textContent = 'Delete';
            deleteButton.onclick = () =>
                deleteRecord(item.collection,item.id);

            top.appendChild(deleteButton);
            card.appendChild(top);

            addText(card,'p',item.timestamp,'note');

            if (item.url) addText(card,'p',item.url,'note');

            addText(card,'label','Request Payload');
            addText(card,'pre',item.payload || item.requestPayload || {});

            addText(card,'label','Response Payload');
            addText(card,'pre',item.responsePayload || {});

            if (item.diagnosticError) {
                addText(card,'p',item.diagnosticError,'failure');
            }

            container.appendChild(card);
        });

    } catch (error) {
        container.textContent = 'Unable to load execution history.';
    }
}

toggleAuth();
toggleBody();
loadLogs();
</script>
</body>
</html>`);
});

// ---------------- START SERVER ----------------

async function startServer() {
    await loadDatabase();

    app.listen(PORT, () => {
        console.log('NexRelay running on port ' + PORT);
        console.log('Database file: ' + DB_FILE);

        if (!INBOUND_TOKEN) {
            console.warn('WARNING: INBOUND_TOKEN is not configured.');
        }
    });
}

startServer().catch(error => {
    console.error('Unable to start NexRelay:', error);
    process.exit(1);
});