/**
 * Node.js DNS Blocker Server - Final Termux Version
 * Features: DNS filtering, Admin API, Heuristics, Client Tracking.
 * STORAGE: Uses Rotating Daily Log Files (JSONL) to avoid all compilation errors.
 * * * REQUIRED PACKAGES: express, dns-packet
 * * TO RUN: 
 * 1. npm install express dns-packet
 * 2. sudo node server.js
 */

const dgram = require('dgram');
const dnsPacket = require('dns-packet');
const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// --- Configuration ---
const ADMIN_PORT = 3000;
const DNS_PORT = 53; 
const UPSTREAM_DNS_SERVER = '8.8.8.8'; 
const UPSTREAM_DNS_PORT = 53;
const IP_API_URL = 'https://api.ipify.org?format=json';
const LOCAL_BLOCKLIST_FILE = 'local_blocklist.txt'; 
const LOG_DIR = path.join(__dirname, 'logs'); // Folder for log files

// --- Server State ---
let dnsServer = dgram.createSocket('udp4');
let dnsActive = true;
let currentPublicIp = 'Unknown';
let BLOCKLIST = new Set();
let CLIENT_DENY_LIST = new Set(); 
let CLIENT_LOG = new Map(); 

let lastListUpdateTime = 'N/A';
let lastListUpdateSource = 'Startup (Empty)';

// Initialize Express App
const app = express();
app.use(express.json());

// --- File System Logging System ---

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR);
}

/**
 * Generates the filename for the current date (e.g., "2023-10-27.jsonl")
 */
function getLogFilename() {
    const date = new Date().toISOString().split('T')[0];
    return path.join(LOG_DIR, `${date}.jsonl`);
}

/**
 * Appends a log entry to the daily file
 */
function logEvent(message, type = 'info') {
    const timestamp = new Date();
    const entry = {
        timestamp: timestamp.toISOString(),
        timeString: timestamp.toLocaleTimeString(),
        message: message,
        type: type
    };

    // 1. Console Log
    const color = {
        'blocked': '\x1b[31m', 'error': '\x1b[33m', 'change': '\x1b[36m',  
        'heuristic': '\x1b[35m', 'client_denied': '\x1b[41m\x1b[37m', 'info': '\x1b[32m'     
    }[type] || '\x1b[0m';
    console.log(`${color}[${entry.timeString}] [${type.toUpperCase()}] ${message}\x1b[0m`);

    // 2. File Log (JSON Line)
    const logLine = JSON.stringify(entry) + '\n';
    fs.appendFile(getLogFilename(), logLine, (err) => {
        if (err) console.error("Failed to write to log file:", err);
    });
}

/**
 * Reads the last N entries from the current log file for the Admin UI
 */
async function getRecentLogs(limit = 50) {
    const filename = getLogFilename();
    if (!fs.existsSync(filename)) return [];

    const logs = [];
    const fileStream = fs.createReadStream(filename);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    for await (const line of rl) {
        try {
            logs.push(JSON.parse(line));
        } catch (e) { /* Ignore corrupt lines */ }
    }

    // Return the last N logs, reversed (newest first)
    return logs.slice(-limit).reverse();
}

// --- Heuristics & Blocklist Logic (Standard) ---

function calculateEntropy(str) {
    if (!str) return 0;
    const frequencies = {};
    for (const char of str) frequencies[char] = (frequencies[char] || 0) + 1;
    return Object.values(frequencies).reduce((sum, f) => {
        const p = f / str.length;
        return sum - p * Math.log2(p);
    }, 0);
}

function isDomainSuspicious(domain) {
    const parts = domain.split('.');
    if (parts.length < 2) return null; 
    const hostname = parts[0]; 
    if (hostname.length > 18) return `Length Heuristic (${hostname.length})`; 
    if (calculateEntropy(hostname) > 3.5) return `High Entropy`; 
    if (/\d{8,}/.test(hostname)) return "Long Number String"; 
    return null; 
}

// --- DNS Server Logic ---

function handleDnsMessage(msg, rinfo) {
    if (!dnsActive) return;

    try {
        const clientIp = rinfo.address;
        CLIENT_LOG.set(clientIp, Date.now()); // Track client
        
        const query = dnsPacket.decode(msg);
        const domain = query.questions[0].name.toLowerCase(); 

        const sendBlockedResponse = (type, reason) => {
            logEvent(`${type} request: ${domain} from ${clientIp} (${reason})`, type);
            const blockedResponse = dnsPacket.encode({
                id: query.id,
                type: 'response', flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RECURSION_AVAILABLE,
                answers: [], rcode: 'NXDOMAIN'
            });
            dnsServer.send(blockedResponse, rinfo.port, rinfo.address, (err) => {});
        };

        if (CLIENT_DENY_LIST.has(clientIp)) return sendBlockedResponse('client_denied', 'Client IP Ban');
        if (BLOCKLIST.has(domain)) return sendBlockedResponse('blocked', 'Static Blocklist');
        
        const suspicious = isDomainSuspicious(domain);
        if (suspicious) return sendBlockedResponse('heuristic', suspicious);
        
        // Forward Upstream
        const forwardSocket = dgram.createSocket('udp4');
        forwardSocket.send(msg, UPSTREAM_DNS_PORT, UPSTREAM_DNS_SERVER);
        forwardSocket.on('message', (resp) => {
            dnsServer.send(resp, rinfo.port, rinfo.address, () => forwardSocket.close());
        });
        forwardSocket.on('error', () => forwardSocket.close());

    } catch (error) {
        logEvent(`DNS Error: ${error.message}`, 'error');
    }
}

dnsServer.on('message', handleDnsMessage);

// --- Express API Endpoints ---

// Serve Admin UI
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// Status API
app.get('/api/status', async (req, res) => {
    const history = await getRecentLogs(50);
    const clients = Array.from(CLIENT_LOG.entries()).map(([ip, lastSeen]) => ({
        ip, lastSeen, isDenied: CLIENT_DENY_LIST.has(ip),
    }));

    res.json({
        ip: currentPublicIp,
        dnsActive: dnsActive,
        blocklistSize: BLOCKLIST.size,
        lastListUpdateTime: lastListUpdateTime,
        history: history,
        clients: clients
    });
});

// Helper Functions for Control
function loadBlocklistFromFile(filepath) {
    try {
        if(!fs.existsSync(filepath)) return;
        const content = fs.readFileSync(filepath, 'utf8');
        const lines = content.split('\n');
        const oldSize = BLOCKLIST.size;
        lines.forEach(line => {
            const clean = line.trim().split(/\s+/).pop();
            if(clean && clean.length > 3 && !clean.startsWith('#')) BLOCKLIST.add(clean.toLowerCase());
        });
        logEvent(`Loaded local blocklist. Total: ${BLOCKLIST.size} (+${BLOCKLIST.size - oldSize})`, 'info');
        lastListUpdateTime = new Date().toLocaleTimeString();
    } catch(e) { logEvent(`Failed to load local list: ${e.message}`, 'error'); }
}

async function loadBlocklistFromUrl(url) {
    try {
        const res = await fetch(url);
        if(!res.ok) throw new Error(res.status);
        const text = await res.text();
        const oldSize = BLOCKLIST.size;
        text.split('\n').forEach(line => {
            const clean = line.trim().split(/\s+/).pop();
            if(clean && clean.length > 3 && !clean.startsWith('#')) BLOCKLIST.add(clean.toLowerCase());
        });
        logEvent(`Downloaded list. Total: ${BLOCKLIST.size} (+${BLOCKLIST.size - oldSize})`, 'info');
    } catch(e) { logEvent(`Download failed: ${e.message}`, 'error'); }
}

// API: Blocklist Control
app.get('/api/blocklist', (req, res) => res.json({ blocklist: Array.from(BLOCKLIST) }));
app.post('/api/blocklist', (req, res) => {
    const { domain, action } = req.body;
    if (action === 'add') { BLOCKLIST.add(domain); logEvent(`Blocked: ${domain}`); }
    if (action === 'remove') { BLOCKLIST.delete(domain); logEvent(`Unblocked: ${domain}`); }
    res.json({ success: true, blocklistSize: BLOCKLIST.size });
});
app.post('/api/load-blocklist', (req, res) => {
    loadBlocklistFromUrl(req.body.url);
    res.json({ success: true, message: 'Downloading...' });
});

// API: Client Control
app.post('/api/client/control', (req, res) => {
    const { ip, action } = req.body;
    if(action === 'block') CLIENT_DENY_LIST.add(ip);
    if(action === 'unblock') CLIENT_DENY_LIST.delete(ip);
    if(action === 'block_all') CLIENT_LOG.forEach((_, k) => CLIENT_DENY_LIST.add(k));
    if(action === 'unblock_all') CLIENT_DENY_LIST.clear();
    res.json({ success: true });
});

app.post('/api/control', (req, res) => {
    if(req.body.action === 'stop') { dnsActive = false; logEvent('DNS Paused'); }
    else { dnsActive = true; logEvent('DNS Started'); }
    res.json({ success: true, dnsActive });
});

// --- Startup ---

// Load local list
loadBlocklistFromFile(LOCAL_BLOCKLIST_FILE);

// Check Public IP
fetch(IP_API_URL).then(r => r.json()).then(d => {
    currentPublicIp = d.ip;
    logEvent(`Public IP: ${currentPublicIp}`);
}).catch(e => {});

// Start Servers
try {
    dnsServer.bind(DNS_PORT, () => console.log(`DNS Listening on 53`));
} catch(e) { console.error("Failed to bind 53. Run with SUDO."); }

app.listen(ADMIN_PORT, () => {
    console.log(`Admin UI: http://localhost:${ADMIN_PORT}`);
    logEvent(`Server Started. Logging to ${LOG_DIR}`);
});
