const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Token for Authenticating Incoming Webhooks
const SECURE_API_KEY = "OmniBridge_Secret_Token_2026";

app.use(cors());
app.use(bodyParser.json());

const webhookLogs = [];

// 1. Secure Inbound Webhook Listener Endpoint
app.post('/api/webhook/:platform', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    // Validate Bearer Token
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        console.warn(`[Unauthorized Attempt] Blocked request to /api/webhook/${req.params.platform}`);
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Unauthorized: Invalid or missing API key' 
        });
    }

    const platform = req.params.platform;
    const payload = req.body;
    
    const logEntry = {
        id: Date.now().toString(),
        platform: platform.toUpperCase(),
        timestamp: new Date().toLocaleTimeString(),
        headers: req.headers,
        payload: payload
    };

    webhookLogs.unshift(logEntry);
    console.log(`[Webhook Received] Platform: ${platform.toUpperCase()}`, payload);

    res.status(200).json({ 
        status: 'Success', 
        message: 'Webhook received securely by OmniBridge Sandbox',
        receivedAt: logEntry.timestamp 
    });
});

// 2. Fetch Logs API
app.get('/api/logs', (req, res) => {
    res.json(webhookLogs);
});

// 3. Secure Interactive Homepage with Test Dispatcher
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>OmniBridge Integration Sandbox</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
                .container { max-width: 1000px; margin: 0 auto; }
                header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 15px; margin-bottom: 20px; }
                h1 { margin: 0; font-size: 22px; color: #38bdf8; }
                .credit { color: #94a3b8; font-size: 14px; }
                .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
                pre { background: #0f172a; padding: 10px; border-radius: 6px; overflow-x: auto; color: #38bdf8; font-size: 13px; }
                .badge { background: #0284c7; color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
                .time { color: #94a3b8; font-size: 12px; float: right; }
                button { background: #38bdf8; color: #0f172a; border: none; padding: 10px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; margin-bottom: 20px; }
                button:hover:not(:disabled) { background: #7dd3fc; }
                button:disabled { background: #64748b; cursor: not-allowed; }
                .empty { text-align: center; color: #64748b; padding: 40px; }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div>
                        <h1>OmniBridge Integration Sandbox</h1>
                        <span class="credit">Architected by Chadaram Veera Pavan</span>
                    </div>
                    <div style="background: #166534; color: #4ade80; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold;">● Secure Cloud Listener Active</div>
                </header>

                <div class="card" style="background: #0f172a; border-color: #0284c7;">
                    <h3 style="margin-top: 0; color: #38bdf8;">Interactive Sandbox Function</h3>
                    <p style="color: #94a3b8; font-size: 14px;">Test your secure endpoint right from the homepage by firing an authorized webhook payload.</p>
                    <button id="test-btn" onclick="triggerTestWebhook()">Dispatch Test Webhook</button>
                </div>

                <h2>Live Secure Inbound Feed</h2>
                <div id="log-feed">
                    <div class="empty">Waiting for incoming webhooks...</div>
                </div>
            </div>
            <script>
                async function triggerTestWebhook() {
                    const btn = document.getElementById('test-btn');
                    if (btn.disabled) return;
                    
                    btn.disabled = true;
                    btn.innerText = "Dispatching...";
                    
                    try {
                        await fetch('/api/webhook/test-client', {
                            method: 'POST',
                            headers: { 
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer OmniBridge_Secret_Token_2026'
                            },
                            body: JSON.stringify({ source: "Homepage Tester", event: "ping", status: "success", user: "Chadaram Veera Pavan" })
                        });
                        fetchLogs();
                    } catch (e) { 
                        console.error(e); 
                    } finally {
                        btn.disabled = false;
                        btn.innerText = "Dispatch Test Webhook";
                    }
                }

                async function fetchLogs() {
                    try {
                        const res = await fetch('/api/logs');
                        const logs = await res.json();
                        const feed = document.getElementById('log-feed');
                        if (logs.length === 0) {
                            feed.innerHTML = '<div class="empty">Waiting for incoming webhooks...</div>';
                            return;
                        }
                        feed.innerHTML = logs.map(l => \`
                            <div class="card">
                                <span class="badge">\${l.platform}</span>
                                <span class="time">\${l.timestamp}</span>
                                <h3 style="margin: 10px 0 5px 0; font-size: 15px;">Event ID: \${l.id}</h3>
                                <pre>\${JSON.stringify(l.payload, null, 2)}</pre>
                            </div>
                        \`).join('');
                    } catch (e) { console.error(e); }
                }
                setInterval(fetchLogs, 2000);
                fetchLogs();
            </script>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`Secure OmniBridge Server running on port ${PORT}`);
});