const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Cryptographically Secure High-Entropy Token (Virtually uncrackable)
const SECURE_API_KEY = "omni_" + crypto.randomBytes(32).toString('hex');
console.log(`[Security] Generated Secure API Key: ${SECURE_API_KEY}`);

app.use(cors());
app.use(bodyParser.json());

let payloadLogs = [];

// 1. Secure Inbound Event Listener Endpoint
app.post('/api/endpoint/:platform', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${SECURE_API_KEY}`) {
        console.warn(`[Unauthorized Attempt] Blocked request to /api/endpoint/${req.params.platform}`);
        return res.status(401).json({ 
            status: 'Error', 
            message: 'Unauthorized: Invalid or missing high-security token' 
        });
    }

    const platform = req.params.platform;
    const data = req.body;
    
    const logEntry = {
        id: Date.now().toString(),
        platform: platform.toUpperCase(),
        timestamp: new Date().toLocaleTimeString(),
        headers: req.headers,
        payload: data
    };

    payloadLogs.unshift(logEntry);
    console.log(`[Event Received] Platform: ${platform.toUpperCase()}`, data);

    res.status(200).json({ 
        status: 'Success', 
        message: 'Payload received securely by OmniBridge Sandbox',
        receivedAt: logEntry.timestamp 
    });
});

// 2. Fetch Logs API
app.get('/api/logs', (req, res) => {
    res.json(payloadLogs);
});

// 3. High-End Interactive Homepage with Custom Cursor & Animations
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>OmniBridge Integration Sandbox</title>
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

                /* Custom High-End Glowing Cursor */
                .cursor-dot, .cursor-outline {
                    position: fixed;
                    top: 0; left: 0;
                    transform: translate(-50%, -50%);
                    border-radius: 50%;
                    pointer-events: none;
                    z-index: 9999;
                    transition: transform 0.1s ease, width 0.2s ease, height 0.2s ease, background-color 0.2s ease;
                }
                .cursor-dot {
                    width: 8px; height: 8px;
                    background: var(--accent);
                }
                .cursor-outline {
                    width: 36px; height: 36px;
                    border: 2px solid rgba(56, 189, 248, 0.4);
                    background: var(--accent-glow);
                    backdrop-filter: blur(2px);
                }

                /* Hover state for interactive items */
                body.hovering .cursor-outline {
                    width: 55px; height: 55px;
                    background: rgba(56, 189, 248, 0.25);
                    border-color: var(--accent);
                }

                .container { max-width: 1050px; margin: 0 auto; position: relative; z-index: 1; }

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
                    box-shadow: 0 0 15px rgba(74, 222, 128, 0.1);
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
                    transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.3s ease, box-shadow 0.3s ease;
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

                pre {
                    background: #020617;
                    padding: 14px;
                    border-radius: 8px;
                    overflow-x: auto;
                    color: #38bdf8;
                    font-size: 13px;
                    border: 1px solid rgba(51, 65, 85, 0.5);
                    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
                }

                .badge {
                    background: rgba(2, 132, 199, 0.2);
                    border: 1px solid rgba(56, 189, 248, 0.3);
                    color: var(--accent);
                    padding: 4px 10px;
                    border-radius: 6px;
                    font-size: 11px;
                    font-weight: 700;
                    letter-spacing: 0.5px;
                }

                .time { color: var(--text-dim); font-size: 12px; float: right; font-weight: 500; }
                .empty { text-align: center; color: var(--text-dim); padding: 50px; font-style: italic; font-size: 14px; }

                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .fade-in { animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
            </style>
        </head>
        <body>
            <div class="cursor-dot" id="cursor-dot"></div>
            <div class="cursor-outline" id="cursor-outline"></div>

            <div class="container">
                <header>
                    <div>
                        <h1>OmniBridge Integration Sandbox</h1>
                        <span class="credit">Architected by Chadaram Veera Pavan</span>
                    </div>
                    <div class="status-badge">
                        <div class="status-dot"></div>
                        Secure Cloud Listener Active
                    </div>
                </header>

                <div class="card" style="border-color: rgba(56, 189, 248, 0.3);">
                    <h3 style="margin-top: 0; color: var(--accent); font-size: 16px;">Interactive Sandbox Control</h3>
                    <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 16px;">Trigger an authenticated test payload transmission to verify end-to-end connectivity instantly.</p>
                    <button id="test-btn" onclick="simulatePayload()">Simulate ServiceNow Payload</button>
                </div>

                <h2 style="font-size: 18px; font-weight: 600; margin-top: 30px; margin-bottom: 15px; color: #cbd5e1;">Live Secure Inbound Feed</h2>
                <div id="log-feed">
                    <div class="empty">Page clear. Waiting for incoming data...</div>
                </div>
            </div>

            <script>
                // Custom Smooth Cursor Tracking & Hover Effects
                const cursorDot = document.getElementById('cursor-dot');
                const cursorOutline = document.getElementById('cursor-outline');

                window.addEventListener('mousemove', (e) => {
                    const posX = e.clientX;
                    const posY = e.clientY;

                    cursorDot.style.left = \`\${posX}px\`;
                    cursorDot.style.top = \`\${posY}px\`;

                    cursorOutline.animate({
                        left: \`\${posX}px\`,
                        top: \`\${posY}px\`
                    }, { duration: 500, fill: "forwards" });
                });

                document.querySelectorAll('button, a, input').forEach(el => {
                    el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
                    el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
                });

                // Simulation Trigger Function
                async function simulatePayload() {
                    const btn = document.getElementById('test-btn');
                    if (btn.disabled) return;
                    
                    btn.disabled = true;
                    btn.innerText = "Transmitting Payload...";
                    
                    try {
                        const response = await fetch('/api/endpoint/servicenow', {
                            method: 'POST',
                            headers: { 
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + '${SECURE_API_KEY}'
                            },
                            body: JSON.stringify({ 
                                source: "Interactive Homepage Simulator", 
                                incident: "INC0010942",
                                short_description: "Network connectivity timeout on primary gateway",
                                priority: "2 - High", 
                                state: "New",
                                user: "Chadaram Veera Pavan",
                                securityLevel: "High-Entropy Cryptographic Token"
                            })
                        });
                        
                        if (response.ok) {
                            await fetchLogs();
                        }
                    } catch (e) { 
                        console.error(e); 
                    } finally {
                        btn.disabled = false;
                        btn.innerText = "Simulate ServiceNow Payload";
                    }
                }

                async function fetchLogs() {
                    try {
                        const res = await fetch('/api/logs');
                        const logs = await res.json();
                        const feed = document.getElementById('log-feed');
                        if (!logs || logs.length === 0) {
                            feed.innerHTML = '<div class="empty">Page clear. Waiting for incoming data...</div>';
                            return;
                        }
                        feed.innerHTML = logs.map(l => \`
                            <div class="card fade-in">
                                <span class="badge">\${l.platform}</span>
                                <span class="time">\${l.timestamp}</span>
                                <h3 style="margin: 12px 0 8px 0; font-size: 14px; font-weight: 600; color: #e2e8f0;">Event ID: \${l.id}</h3>
                                <pre>\${JSON.stringify(l.payload, null, 2)}</pre>
                            </div>
                        \`).join('');
                    } catch (e) { console.error(e); }
                }

                fetchLogs();
            </script>
        </body>
        </html>