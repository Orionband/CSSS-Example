const dotenv = require('dotenv');
dotenv.config(); 

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');

const db = require('./database');
const { getConfig, getRawConfig, isWindowOpen } = require('./config');
const authRoutes = require('./routes/auth');
const quizRoutes = require('./routes/quiz');

const app = express();
app.set('trust proxy', true);
const server = http.createServer(app);

const cfgInitial = getConfig();
let globalMaxUploadMB = 75;
(cfgInitial.labs || []).forEach(l => {
    if (l.max_upload_mb && l.max_upload_mb > globalMaxUploadMB) {
        globalMaxUploadMB = l.max_upload_mb;
    }
});

const io = new Server(server, { maxHttpBufferSize: globalMaxUploadMB * 1024 * 1024 }); 

app.use(express.json());

const sessionMiddleware = session({
    store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 900000 } }),
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,  
        secure: 'auto',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self' ws: wss:; " +
        "frame-ancestors 'none';"
    );
    next();
});

// CSRF token generation
app.use((req, res, next) => {
    if (req.session && !req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    next();
});

// CSRF validation for state-changing requests
app.use((req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    
    const clientToken = req.headers['x-csrf-token'] || (req.body && req.body._csrf);
    
    if (!req.session || !req.session.csrfToken || clientToken !== req.session.csrfToken) {
        return res.status(403).json({ error: "Invalid or missing CSRF token." });
    }
    
    next();
});

app.use(express.static(path.join(__dirname, '../public')));
app.use('/api', authRoutes);
app.use('/api/quiz', quizRoutes);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../index.html')));

const MAX_WORKERS = parseInt(process.env.MAX_WORKERS) || 4;
let activeWorkers = 0;
const workerQueue = [];
const MAX_QUEUE_DEPTH = parseInt(process.env.MAX_QUEUE_DEPTH) || 50;

function processWorkerQueue() {
    if (workerQueue.length === 0 || activeWorkers >= MAX_WORKERS) return;
    activeWorkers++;
    
    const task = workerQueue.shift();
    const { socket, workerData, lockKey, socketUser, targetLab, inProgressId } = task;

    const WORKER_TIMEOUT_MS = 120000;
    const worker = new Worker(path.join(__dirname, 'worker/worker.js'), { workerData });

    const timeoutHandle = setTimeout(() => {
        socket.emit('err', "Processing timed out.");
        db.releaseLock(lockKey);
        worker.terminate();
        activeWorkers--;
        processWorkerQueue();
    }, WORKER_TIMEOUT_MS);

    worker.on('message', (msg) => {
        if (msg.type === 'progress') socket.emit('progress', msg);
        else if (msg.type === 'result') {
            clearTimeout(timeoutHandle);
            const { grading } = msg;
            const timestamp = Date.now();
            const capturesDir = path.join(__dirname, '../captures');

            if (inProgressId) {
                db.prepare("UPDATE submissions SET score = ?, max_score = ?, details = ?, status = 'completed' WHERE id = ?")
                    .run(grading.total, grading.max, JSON.stringify(grading.serverBreakdown), inProgressId);
            } else {
                db.prepare('INSERT INTO submissions (user_id, unique_id, lab_id, score, max_score, details, type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                    .run(socketUser.id, socketUser.unique_id, targetLab.id, grading.total, grading.max, JSON.stringify(grading.serverBreakdown), 'lab', 'completed');
            }

            if (process.env.RETAIN_PKA === 'true' || process.env.RETAIN_XML === 'true') {
                if (!fs.existsSync(capturesDir)) fs.mkdirSync(capturesDir, { recursive: true });
                const safeTitle = targetLab.title.replace(/[^a-z0-9]/gi, '_');
                const baseName = `${safeTitle}_${socketUser.unique_id}_${timestamp}`;
                 if (process.env.RETAIN_PKA === 'true') {
					fs.writeFileSync(path.join(capturesDir, `${baseName}.pka`), Buffer.from(workerData.fileData));

					// Also retain PKT when PKA is retained
					fs.writeFileSync(path.join(capturesDir, `${baseName}.pkt`), Buffer.from(workerData.fileData));
				}
                if (process.env.RETAIN_XML === 'true') fs.writeFileSync(path.join(capturesDir, `${baseName}.xml`), msg.xml);
            }

            const payload = { 
                total: grading.total, max: grading.max, clientBreakdown: grading.clientBreakdown, show_score: grading.show_score
            };

            if (!grading.show_score) { delete payload.total; delete payload.max; }

            socket.emit('result', payload);
            db.releaseLock(lockKey); 
            worker.terminate();
            activeWorkers--;
            processWorkerQueue();
        } else if (msg.type === 'error') {
            clearTimeout(timeoutHandle);
            socket.emit('err', msg.msg);
            db.releaseLock(lockKey); 
            worker.terminate();
            activeWorkers--;
            processWorkerQueue();
        }
    });
    
    worker.on('error', (e) => {
        clearTimeout(timeoutHandle);
        socket.emit('err', "An internal processing error occurred.");
        db.releaseLock(lockKey); 
        worker.terminate();
        activeWorkers--;
        processWorkerQueue();
    });
}

// Sweepers
setInterval(() => {
    try {
        db.prepare("DELETE FROM active_locks WHERE timestamp < datetime('now', '-5 minutes')").run();
        
        const cfg = getConfig();
        const labs = cfg.labs || [];
        const inProgress = db.prepare("SELECT * FROM submissions WHERE status = 'in_progress' AND type = 'lab'").all();

        inProgress.forEach(sub => {
            const labCfg = labs.find(l => l.id === sub.lab_id);
            if (labCfg) {
                let closeSession = false;
                let reason = "";

                if (labCfg.time_limit_minutes && labCfg.time_limit_minutes > 0) {
                    const startTime = new Date(sub.timestamp.replace(' ', 'T') + 'Z').getTime();
                    const elapsed = Math.floor((Date.now() - startTime) / 1000);
                    if (elapsed > (labCfg.time_limit_minutes * 60) + 2) {
                        closeSession = true;
                        reason = "Auto-closed: Time limit expired.";
                    }
                }

                if (!isWindowOpen(labCfg)) {
                    closeSession = true;
                    reason = "Auto-closed: Competition window ended.";
                }

                if (closeSession) {
                    db.prepare("UPDATE submissions SET status = 'completed', score = 0, max_score = 0, details = ? WHERE id = ?")
                        .run(JSON.stringify([{message: reason, device: "N/A", possible: 0, awarded: 0, passed: false}]), sub.id);
                }
            }
        });
    } catch (e) {
        console.error("Error in sweeping routines:", e.message);
    }
}, 60 * 1000);

io.on('connection', (socket) => {
    let socketUser = null;
    let isAuthenticated = false;
    let authInProgress = false;

    socket.on('authenticate', () => {
        if (authInProgress) return;
        authInProgress = true;

        const sess = socket.request.session;
        if (sess && sess.userId && sess.uniqueId) {
            const user = db.prepare('SELECT * FROM users WHERE id = ?').get(sess.userId);
            if (user) {
                socketUser = user;
                isAuthenticated = true;
                authInProgress = false;
                socket.emit('auth_success', user.unique_id);
                return;
            }
        }
        authInProgress = false;
        socket.emit('auth_fail');
    });

    socket.on('upload_file', (packet) => {
        if (!isAuthenticated || !socketUser) return socket.emit('err', "Unauthorized");
        
        const sess = socket.request.session;
        if (!sess || !sess.userId || sess.userId !== socketUser.id) {
            isAuthenticated = false;
            socketUser = null;
            return socket.emit('err', "Session expired. Please refresh and log in again.");
        }

        const clientToken = packet._csrf;
        if (!clientToken || clientToken !== sess.csrfToken) {
            return socket.emit('err', "Invalid CSRF token. Please refresh the page.");
        }

        const fileData = packet.fileData || packet;
        const cfg = getConfig();
        const labs = cfg.labs || [];
        const labId = packet.labId || (labs.length > 0 ? labs[0].id : null);
        const userId = socketUser.id;

        if (!labId) return socket.emit('err', "No configuration loaded.");

        const targetLab = labs.find(l => l.id === labId);
        if (!targetLab) return socket.emit('err', "Invalid Lab ID.");

        if (!isWindowOpen(targetLab)) {
            return socket.emit('err', "Submissions are currently closed outside of the competition window.");
        }

        const labMaxMb = targetLab.max_upload_mb || 75;
        if (Buffer.byteLength(fileData) > labMaxMb * 1024 * 1024) {
            return socket.emit('err', `File exceeds the maximum allowed size for this lab.`);
        }

        const lockKey = `lab_${userId}_${labId}`;
        if (!db.acquireLock(lockKey)) {
            return socket.emit('err', "A submission is currently processing. Please wait.");
        }

        try {
            if (workerQueue.length >= MAX_QUEUE_DEPTH) {
                db.releaseLock(lockKey);
                return socket.emit('err', "Server is busy. Please try again in a moment.");
            }

            let inProgressId = null;
            const activeSession = db.prepare("SELECT id, timestamp FROM submissions WHERE user_id = ? AND lab_id = ? AND status = 'in_progress' AND type = 'lab' ORDER BY id DESC LIMIT 1")
                .get(userId, labId);

            if (activeSession) {
                if (targetLab.time_limit_minutes && targetLab.time_limit_minutes > 0) {
                    const startTime = new Date(activeSession.timestamp.replace(' ', 'T') + 'Z').getTime();
                    const elapsed = Math.floor((Date.now() - startTime) / 1000);

                    if (elapsed > (targetLab.time_limit_minutes * 60) + 2) {
                        db.prepare("UPDATE submissions SET status = 'completed', score = 0, max_score = 0, details = ? WHERE id = ?")
                            .run(JSON.stringify([{message: "Time expired on submission.", device: "N/A", possible: 0, awarded: 0, passed: false}]), activeSession.id);
                        db.releaseLock(lockKey);
                        return socket.emit('err', "Time limit expired. Your submission was rejected.");
                    }
                }
                inProgressId = activeSession.id;
            } else {
                if (targetLab.time_limit_minutes && targetLab.time_limit_minutes > 0) {
                    db.releaseLock(lockKey);
                    return socket.emit('err', "No active lab session. Please start the lab first.");
                }

                const canSubmit = db.transaction((uid, lid, maxSubs, rateLimitCount, rateLimitWindow) => {
                    if (maxSubs > 0) {
                        const count = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE user_id = ? AND lab_id = ?').get(uid, lid).c;
                        if (count >= maxSubs) return { allowed: false, reason: "Submission limit reached." };
                    }
                    if (rateLimitCount > 0) {
                        const win = rateLimitWindow || 60;
                        const recent = db.prepare("SELECT COUNT(*) as c FROM submissions WHERE user_id = ? AND lab_id = ? AND timestamp > datetime('now', '-' || ? || ' seconds')").get(uid, lid, win).c;
                        if (recent >= rateLimitCount) return { allowed: false, reason: "Rate limit exceeded. Please wait." };
                    }
                    return { allowed: true };
                });

                const maxSubs = targetLab.max_submissions || 0;
                const rateLimitCount = targetLab.rate_limit_count || 0;
                const rateLimitWindow = targetLab.rate_limit_window_seconds || 60;
                
                const check = canSubmit(userId, labId, maxSubs, rateLimitCount, rateLimitWindow);
                if (!check.allowed) {
                    db.releaseLock(lockKey);
                    return socket.emit('err', check.reason);
                }
            }

            const maxXmlMb = targetLab.max_xml_output_mb || 20;

            workerQueue.push({ 
                socket, 
                workerData: { fileData, configData: getRawConfig(), labId, maxXmlMb }, 
                lockKey, socketUser, targetLab, inProgressId 
            });
            processWorkerQueue();

        } catch (err) {
            db.releaseLock(lockKey);
            socket.emit('err', "An internal error occurred.");
        }
    });
});

setInterval(() => {
    const capturesDir = path.join(__dirname, '../captures');
    if (fs.existsSync(capturesDir)) {
        const now = Date.now();
        fs.readdir(capturesDir, (err, files) => {
            if (err) return;
            files.forEach(file => {
                const filePath = path.join(capturesDir, file);
                fs.stat(filePath, (err, stats) => {
                    if (err) return;
                    if (now - stats.mtimeMs > 30 * 24 * 60 * 60 * 1000) fs.unlink(filePath, () => {});
                });
            });
        });
    }
}, 24 * 60 * 60 * 1000);

const PORT = 10000;
server.listen(PORT, () => console.log(`CSSS Server running on http://localhost:${PORT}`));