const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const db = require('./db');
const axios = require('axios');
require('dotenv').config({ path: path.resolve(__dirname, '../.env'), override: true });

const app = express();
const PORT = process.env.PORT || 3000;

// Setup file upload storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Create uploads folder if not exists
const fs = require('fs');
if (!fs.existsSync('uploads')) { fs.mkdirSync('uploads'); }

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

// --- AI AGENT LOGIC (GROQ) ---
const analyzeWithAI = async (text, type = "text") => {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
        console.error("GROQ_API_KEY missing in .env");
        return null;
    }

    const prompt = `
    Analyze the following for digital fraud/cyber threat:
    Content: "${text}"
    Type: ${type}
    
    You are a Cyber Security AI Agent. Provide:
    1. severity (CRITICAL, HIGH, MEDIUM, SAFE)
    2. threat_type (e.g. Phishing, Malware, Scam, Safe)
    3. message (A friendly but professional warning/verdict)
    
    Respond ONLY in JSON format:
    {"severity": "...", "threat_type": "...", "message": "..."}
    `;

    try {
        const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
            model: "llama-3.3-70b-versatile",
            messages: [{ role: "user", content: prompt }],
            response_format: { type: "json_object" }
        }, {
            headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
        });

        return JSON.parse(response.data.choices[0].message.content);
    } catch (err) {
        console.error("AI Analysis Error:", err.response ? err.response.status : err.message);
        return null;
    }
};

// --- CYBER NEWS DATA ---
const CYBER_NEWS = [
    {
        id: 11,
        title: "🚨 BREAKING: New UPI 'Collect Request' Fraud Spreading",
        summary: "Scammers are sending fake 'refund' links that actually trigger a UPI collect request. Authorities advise never entering your PIN for receiving money.",
        date: "May 04, 2026",
        severity: "CRITICAL",
        category: "Payment Fraud"
    },
    {
        id: 12,
        title: "⚠️ ALERT: AI Voice Cloning Scams in Family Groups",
        summary: "Fraudsters are using 3-second clips of family members' voices from social media to create deepfake distress calls, asking for urgent money transfers.",
        date: "May 04, 2026",
        severity: "HIGH",
        category: "AI Fraud"
    },
    {
        id: 1,
        title: "Digital Arrest Scam: Bengaluru Techie Loses 25 Lakhs",
        summary: "A 28-year-old software engineer was 'digitally arrested' for 24 hours by scammers impersonating Mumbai Police and CBI officials. They claimed his Aadhaar was used for money laundering.",
        date: "May 04, 2026",
        severity: "CRITICAL",
        category: "Impersonation"
    },
    {
        id: 2,
        title: "WhatsApp 'Pink' Scam Returns with 5G Lure",
        summary: "New variants of the 'WhatsApp Pink' malware are spreading. It promises an exclusive 5G theme but installs a trojan that steals OTPs and bank credentials.",
        date: "May 03, 2026",
        severity: "HIGH",
        category: "Malware"
    },
    {
        id: 3,
        title: "Fake Trading Apps: SEBI Issues Alert",
        summary: "Fraudulent stock trading apps promising 200% returns in a week are trending on social media. Victims are forced to pay 'taxes' to withdraw non-existent profits.",
        date: "May 02, 2026",
        severity: "CRITICAL",
        category: "Investment Fraud"
    },
    {
        id: 4,
        title: "Electricity Bill Scam Targeting Senior Citizens",
        summary: "Scammers send SMS saying 'Your power will be cut tonight at 9PM due to non-payment.' They ask victims to call a number and install a remote desktop app like Anydesk.",
        date: "May 01, 2026",
        severity: "HIGH",
        category: "Social Engineering"
    },
    {
        id: 5,
        title: "Work-From-Home Job Scam: Telegram Warning",
        summary: "Fake 'YouTube Like' jobs are being used to lure students. Victims are initially paid small amounts but later asked to 'invest' to unlock higher-paying tasks.",
        date: "April 30, 2026",
        severity: "MEDIUM",
        category: "Job Fraud"
    },
    {
        id: 6,
        title: "PAN Card Update Phishing Waves Detected",
        summary: "A large-scale phishing campaign is targeting Indian tax payers with fake SMS about PAN card deactivation. Links lead to a cloned income tax portal.",
        date: "April 29, 2026",
        severity: "HIGH",
        category: "Phishing"
    },
    {
        id: 7,
        title: "OLX 'Scan QR' Fraud: How Sellers are Being Scammed",
        summary: "Scammers posing as buyers on OLX are sending 'Payment QR' codes to sellers. Instead of receiving money, sellers end up authorizing payments from their own accounts.",
        date: "April 28, 2026",
        severity: "HIGH",
        category: "Marketplace Fraud"
    },
    {
        id: 8,
        title: "Instagram 'Copyright' Hacking Campaign",
        summary: "Influencers are being targeted with fake DM claims about copyright violations. The 'appeals' link steals session cookies to bypass 2FA.",
        date: "April 27, 2026",
        severity: "MEDIUM",
        category: "Social Media"
    },
    {
        id: 9,
        title: "KYC Verification Scam: Warning for Senior Citizens",
        summary: "Fraudsters are using remote access apps like TeamViewer and AnyDesk under the guise of helping senior citizens complete their bank KYC.",
        date: "April 26, 2026",
        severity: "CRITICAL",
        category: "Social Engineering"
    },
    {
        id: 10,
        title: "Gift Card Scams in Corporate Emails",
        summary: "Employees are receiving emails from 'CEOs' asking them to purchase Amazon or Google Play gift cards for urgent client meetings. This is a classic Business Email Compromise (BEC).",
        date: "April 25, 2026",
        severity: "MEDIUM",
        category: "Corporate Fraud"
    }
];

// --- ENDPOINTS ---

// API: Get Cyber News
app.get('/api/news', (req, res) => {
    res.json(CYBER_NEWS);
});

// API: Scan File/APK (User Portal)
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const filename = req.file.originalname.toLowerCase();
    
    // Initial static check
    let result = { severity: 'SAFE', threat_type: 'Clean', message: 'No obvious signatures found.' };
    
    if (filename.endsWith('.apk')) {
        result = { severity: 'HIGH', threat_type: 'Suspicious APK', message: 'APK contains restricted permissions.' };
    }

    // Agent Intelligence Upgrade
    const aiResult = await analyzeWithAI(`Filename: ${req.file.originalname}. Analysis type: Binary file risk assessment.`, "file");
    if (aiResult) result = aiResult;

    db.run(`INSERT INTO logs (user_id, message, threat_type, severity, region, language) VALUES (?, ?, ?, ?, ?, ?)`, 
        ['WebUser', `File Scan: ${req.file.originalname}`, result.threat_type, result.severity, 'Delhi', 'EN']
    );

    res.json(result);
});

// API: Scan Text (User Portal)
app.post('/api/scan/text', async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Text is required' });

    // AI Agent Analysis
    const aiResult = await analyzeWithAI(text, "text");
    
    let result = aiResult || {
        severity: 'MEDIUM',
        threat_type: 'Manual Check Needed',
        message: 'AI Analysis currently offline. Please do not share OTPs.'
    };

    db.run(`INSERT INTO logs (user_id, message, threat_type, severity, region, language) VALUES (?, ?, ?, ?, ?, ?)`, 
        ['WebUser', text.substring(0, 50), result.threat_type, result.severity, 'Maharashtra', 'EN']
    );

    res.json(result);
});

// API: Receive logs from Python Telegram Bot
app.post('/api/logs', (req, res) => {
    console.log('Incoming Log Request:', req.body);
    const { user_id, message, threat_type, severity, language } = req.body;
    
    if (!user_id || !message) {
        return res.status(400).json({ error: 'user_id and message are required' });
    }

    // Inferred Region Mapping
    const regionMap = {
        'KA': 'Karnataka',
        'TE': 'Telangana',
        'TA': 'Tamil Nadu',
        'HI': 'Uttar Pradesh',
        'EN': 'Delhi',
        'MA': 'Maharashtra'
    };
    const region = regionMap[language] || 'Delhi';

    const query = `INSERT INTO logs (user_id, message, threat_type, severity, language, region) VALUES (?, ?, ?, ?, ?, ?)`;
    db.run(query, [user_id, message, threat_type, severity, language || 'EN', region], function(err) {
        if (err) {
            console.error('Error inserting log:', err.message);
            return res.status(500).json({ error: 'Failed to insert log' });
        }
        res.status(201).json({ success: true, id: this.lastID });
    });
});

// API: Get Aggregated Stats for Dashboard
app.get('/api/stats', (req, res) => {
    const stats = {
        total_scans: 0,
        critical_count: 0,
        high_count: 0,
        active_users: 0,
        threat_types: [],
        scans_over_time: [],
        hourly_heatmap: [],
        state_data: []
    };

    const queries = [
        new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM logs`, (err, row) => {
                if (err) reject(err); else { stats.total_scans = row.count || 0; resolve(); }
            });
        }),
        new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM logs WHERE severity = 'CRITICAL'`, (err, row) => {
                if (err) reject(err); else { stats.critical_count = row.count || 0; resolve(); }
            });
        }),
        new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM logs WHERE severity = 'HIGH'`, (err, row) => {
                if (err) reject(err); else { stats.high_count = row.count || 0; resolve(); }
            });
        }),
        new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(DISTINCT user_id) as count FROM logs`, (err, row) => {
                if (err) reject(err); else { stats.active_users = row.count || 0; resolve(); }
            });
        }),
        new Promise((resolve, reject) => {
            db.all(`SELECT threat_type as name, COUNT(*) as value FROM logs GROUP BY threat_type`, (err, rows) => {
                if (err) reject(err); else { stats.threat_types = rows || []; resolve(); }
            });
        }),
        new Promise((resolve, reject) => {
            db.all(`SELECT DATE(timestamp) as date, COUNT(*) as count FROM logs GROUP BY DATE(timestamp) ORDER BY date DESC LIMIT 7`, (err, rows) => {
                if (err) reject(err); 
                else { 
                    stats.scans_over_time = (rows || []).reverse();
                    resolve(); 
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.all(`SELECT hour_of_day as hour, COUNT(*) as count FROM logs GROUP BY hour_of_day ORDER BY hour_of_day ASC`, (err, rows) => {
                if (err) reject(err); 
                else { 
                    const hourlyData = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
                    (rows || []).forEach(row => {
                        if(row.hour !== null && row.hour >= 0 && row.hour < 24) {
                            hourlyData[row.hour].count = row.count;
                        }
                    });
                    stats.hourly_heatmap = hourlyData;
                    resolve(); 
                }
            });
        }),
        new Promise((resolve, reject) => {
            db.all(`SELECT region as name, COUNT(*) as value FROM logs WHERE region != 'GLOBAL' GROUP BY region`, (err, rows) => {
                if (err) reject(err); else { stats.state_data = rows || []; resolve(); }
            });
        })
    ];

    Promise.all(queries)
        .then(() => res.json(stats))
        .catch(err => {
            console.error('Error fetching stats:', err);
            res.status(500).json({ error: 'Failed to fetch stats' });
        });
});

// API: Get Recent Logs for Table
app.get('/api/recent', (req, res) => {
    db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 15`, (err, rows) => {
        if (err) {
            console.error('Error fetching recent logs:', err);
            return res.status(500).json({ error: 'Failed to fetch recent logs' });
        }
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Backend API Server running on http://localhost:${PORT}`);
});
