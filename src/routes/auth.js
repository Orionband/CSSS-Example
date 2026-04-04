const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database');
const { getConfig } = require('../config');
const router = express.Router();
const { customAlphabet } = require('nanoid');
const rateLimit = require('express-rate-limit');

function generateUniqueId() { 
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	const nanoid = customAlphabet(alphabet, 12);
    const id = nanoid();
    return id.match(/.{1,4}/g).join('-');
}

const DUMMY_HASH = bcrypt.hashSync('__dummy_timing_safe_value_never_matches__', 10);

const registerLimiter = rateLimit({ windowMs: 24*60*60*1000, max: 10, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 5*60*1000, max: 5, standardHeaders: true, legacyHeaders: false });

function isWindowOpen(challenge) {
    if (!challenge) return true;
    if (!challenge.comp_start && !challenge.comp_end) return true;
    const now = Date.now();
    if (challenge.comp_start) {
        const start = new Date(challenge.comp_start).getTime();
        if (!isNaN(start) && now < start) return false;
    }
    if (challenge.comp_end) {
        const end = new Date(challenge.comp_end).getTime();
        if (!isNaN(end) && now > end) return false;
    }
    return true;
}

router.get('/csrf-token', (req, res) => {
    if (!req.session) return res.status(500).json({ error: "Session unavailable" });
    if (!req.session.csrfToken) {
        const crypto = require('crypto');
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.json({ csrfToken: req.session.csrfToken });
});

router.post('/register', registerLimiter, async (req, res) => {
    if (process.env.ALLOW_REGISTRATION === 'false') {
        return res.status(403).json({ error: "Registration is currently disabled by the administrator." });
    }

    const { username, email, password } = req.body;
    
    if (!username || !email || password === undefined || password === null) {
        return res.status(400).json({ error: "Missing fields" });
    }
    
    const pwd = String(password);
    const userStr = String(username);
    const emailStr = String(email);

    if (userStr.length > 100 || emailStr.length > 100 || pwd.length > 100) {
        return res.status(400).json({ error: "Fields must be 100 characters or less." });
    }
    
    if (pwd.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters." });
    }
    if (!/[A-Z]/.test(pwd)) {
        return res.status(400).json({ error: "Password must contain at least one uppercase letter." });
    }
    if (!/[0-9]/.test(pwd)) {
        return res.status(400).json({ error: "Password must contain at least one number." });
    }

    try {
        const hashedPassword = await bcrypt.hash(pwd, 10);
        const uid = generateUniqueId();
        const stmt = db.prepare('INSERT INTO users (username, email, password, unique_id) VALUES (?, ?, ?, ?)');
        const info = stmt.run(userStr, emailStr, hashedPassword, uid);
        req.session.userId = info.lastInsertRowid;
        req.session.uniqueId = uid;
        req.session.save((err) => {
            if (err) return res.status(500).json({ error: "Session save failed." });
            res.json({ success: true, unique_id: uid });
        });
    } catch (err) {
        res.status(400).json({ error: "Username or Email already exists" });
    }
});

router.post('/logout', (req, res) => {
    req.session.destroy(err => {
        res.clearCookie('connect.sid'); 
        res.json({ success: true });
    });
});

router.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    const hashToCompare = user ? user.password : DUMMY_HASH;
    
    const pwd = password !== undefined && password !== null ? String(password) : "";
    const passwordMatch = await bcrypt.compare(pwd, hashToCompare);

    if (!user || !passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    req.session.regenerate(err => {
        if (err) return res.status(500).json({ error: "Login failed. Please try again." });
        req.session.userId = user.id;
        req.session.uniqueId = user.unique_id;
        req.session.save((saveErr) => {
            if (saveErr) return res.status(500).json({ error: "Session save failed." });
            res.json({ success: true, unique_id: user.unique_id });
        });
    });
});

router.get('/me', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: "Not logged in" });
    res.json({ id: req.session.userId, unique_id: req.session.uniqueId });
});

router.get('/config', (req, res) => {
    const cfg = getConfig();
    const safeLabs = (cfg.labs || []).map(l => ({ id: l.id, title: l.title, type: 'lab' }));
    
    const safeQuizzes = (cfg.quizzes || []).map(q => ({ id: q.id, title: q.title, type: 'quiz' }));

    const fullTitle = process.env.APP_TITLE || 'CSSS ENGINE';
    const parts = fullTitle.split(' ');
    let titleMain = parts[0] || '';
    let titleHighlight = parts.slice(1).join(' ') || '';

    res.json({ 
        challenges: [...safeLabs, ...safeQuizzes],
        options: { 
            show_leaderboard: process.env.SHOW_LEADERBOARD === 'true',
            show_history: process.env.SHOW_HISTORY === 'true',
            app_title: fullTitle,
            app_title_main: titleMain,
            app_title_highlight: titleHighlight
        }
    });
});

router.get('/lab/:id', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: "Unauthorized" });
    
    const cfg = getConfig();
    const lab = (cfg.labs || []).find(l => l.id === req.params.id);
    if (!lab) return res.status(404).json({ error: "Lab not found." });

    const totalAttempts = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE user_id = ? AND lab_id = ?')
        .get(req.session.userId, lab.id).c;
    
    const activeSession = db.prepare("SELECT id, timestamp FROM submissions WHERE user_id = ? AND lab_id = ? AND status = 'in_progress' AND type = 'lab' ORDER BY id DESC LIMIT 1")
        .get(req.session.userId, lab.id);

    let timeRemaining = null;
    let sessionActive = false;

    if (activeSession) {
        sessionActive = true;
        if (lab.time_limit_minutes && lab.time_limit_minutes > 0) {
            const startTime = new Date(activeSession.timestamp.replace(' ', 'T') + 'Z').getTime();
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            timeRemaining = Math.max(0, (lab.time_limit_minutes * 60) - elapsed);
            
            if (timeRemaining <= 0) {
                db.prepare("UPDATE submissions SET status = 'completed', score = 0, max_score = 0, details = ? WHERE id = ?")
                    .run(JSON.stringify([{message: "Time expired.", device: "N/A", possible: 0, awarded: 0, passed: false}]), activeSession.id);
                sessionActive = false;
                timeRemaining = null;
            }
        }
    }

    res.json({
        id: lab.id,
        title: lab.title,
        max_submissions: lab.max_submissions || 0,
        attempts_taken: totalAttempts,
        time_limit_minutes: lab.time_limit_minutes || 0,
        has_pka_file: !!lab.pka_file,
        session_active: sessionActive,
        time_remaining_seconds: timeRemaining
    });
});

router.post('/lab/:id/start', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: "Unauthorized" });

    const cfg = getConfig();
    const lab = (cfg.labs || []).find(l => l.id === req.params.id);
    if (!lab) return res.status(404).json({ error: "Lab not found." });

    if (!isWindowOpen(lab)) {
        return res.status(403).json({ error: "Lab is currently closed outside of the competition window." });
    }

    const existing = db.prepare("SELECT id, timestamp FROM submissions WHERE user_id = ? AND lab_id = ? AND status = 'in_progress' AND type = 'lab' ORDER BY id DESC LIMIT 1")
        .get(req.session.userId, lab.id);

    if (existing) {
        let timeRemaining = null;
        if (lab.time_limit_minutes && lab.time_limit_minutes > 0) {
            const startTime = new Date(existing.timestamp.replace(' ', 'T') + 'Z').getTime();
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            timeRemaining = Math.max(0, (lab.time_limit_minutes * 60) - elapsed);

            if (timeRemaining <= 0) {
                db.prepare("UPDATE submissions SET status = 'completed', score = 0, max_score = 0, details = ? WHERE id = ?")
                    .run(JSON.stringify([{message: "Time expired.", device: "N/A", possible: 0, awarded: 0, passed: false}]), existing.id);
                return res.status(403).json({ error: "Your previous session has expired." });
            }
        }

        return res.json({
            success: true,
            resumed: true,
            has_pka_file: !!lab.pka_file,
            time_remaining_seconds: timeRemaining
        });
    }

    if (lab.max_submissions && lab.max_submissions > 0) {
        const count = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE user_id = ? AND lab_id = ?')
            .get(req.session.userId, lab.id).c;
        if (count >= lab.max_submissions) {
            return res.status(403).json({ error: "Maximum attempts reached." });
        }
    }

    db.prepare("INSERT INTO submissions (user_id, unique_id, lab_id, status, type) VALUES (?, ?, ?, 'in_progress', 'lab')")
        .run(req.session.userId, req.session.uniqueId, lab.id);

    let timeRemaining = null;
    if (lab.time_limit_minutes && lab.time_limit_minutes > 0) {
        timeRemaining = lab.time_limit_minutes * 60;
    }

    res.json({
        success: true,
        resumed: false,
        has_pka_file: !!lab.pka_file,
        time_remaining_seconds: timeRemaining
    });
});

router.get('/lab/:id/download', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).send("Unauthorized");

    const cfg = getConfig();
    const lab = (cfg.labs || []).find(l => l.id === req.params.id);
    if (!lab) return res.status(404).send("Lab not found.");
    if (!lab.pka_file) return res.status(404).send("No PKA file configured for this lab.");

    const activeSession = db.prepare("SELECT id, timestamp FROM submissions WHERE user_id = ? AND lab_id = ? AND status = 'in_progress' AND type = 'lab' ORDER BY id DESC LIMIT 1")
        .get(req.session.userId, lab.id);

    if (!activeSession) {
        return res.status(403).send("Forbidden: No active lab session. Start the lab first.");
    }

    if (lab.time_limit_minutes && lab.time_limit_minutes > 0) {
        const startTime = new Date(activeSession.timestamp.replace(' ', 'T') + 'Z').getTime();
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        if (elapsed > (lab.time_limit_minutes * 60)) {
            db.prepare("UPDATE submissions SET status = 'completed', score = 0, max_score = 0, details = ? WHERE id = ?")
                .run(JSON.stringify([{message: "Time expired.", device: "N/A", possible: 0, awarded: 0, passed: false}]), activeSession.id);
            return res.status(403).send("Forbidden: Lab session has expired.");
        }
    }

    const path = require('path');
    const fs = require('fs');

    const safeFilename = path.basename(lab.pka_file);
    if (/[/\\:\0]/.test(safeFilename) || safeFilename.startsWith('.')) {
        return res.status(400).send("Invalid file configuration.");
    }

    const baseDir = path.resolve(path.join(__dirname, '../../protected/pka'));
    const filePath = path.resolve(path.join(baseDir, safeFilename));

    if (!filePath.startsWith(baseDir + path.sep) && filePath !== baseDir) {
        return res.status(403).send("Forbidden.");
    }

    try {
        const stats = fs.lstatSync(filePath);
        if (stats.isSymbolicLink()) return res.status(403).send("Forbidden.");
        if (!stats.isFile()) return res.status(404).send("File not found.");
    } catch (e) {
        return res.status(404).send("File not found.");
    }

    res.download(filePath, safeFilename);
});

router.get('/leaderboard', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: "Unauthorized" });
    if (process.env.SHOW_LEADERBOARD !== 'true') {
        return res.status(403).json({ error: "Leaderboard disabled" });
    }
    
    const cfg = getConfig();
    const labs = cfg.labs || [];
    const quizzes = (cfg.quizzes || []).filter(q => q.enabled !== false);
    const allChallenges = [...labs, ...quizzes];

    const users = db.prepare('SELECT id, username FROM users').all();
    const leaderboard = [];

    users.forEach(u => {
        let total = 0;
        const scores = {};
        
        allChallenges.forEach(ch => {
            let hideScore = false;
            if (ch.type === 'quiz') {
                const qCfg = quizzes.find(q => q.id === ch.id);
                if (qCfg && qCfg.show_score === false) hideScore = true;
            } else {
                const lCfg = labs.find(l => l.id === ch.id);
                if (lCfg && lCfg.show_score === false) hideScore = true;
            }

            const row = db.prepare("SELECT MAX(score) as s FROM submissions WHERE user_id = ? AND lab_id = ? AND status = 'completed'").get(u.id, ch.id);
            const score = row && row.s !== null ? row.s : 0;
            
            if (hideScore) {
                scores[ch.id] = '?'; 
            } else {
                scores[ch.id] = score;
                total += score;
            }
        });
        
        if (total > 0 || Object.values(scores).some(s => s === '?')) {
            leaderboard.push({ username: u.username, scores: scores, total_score: total });
        }
    });

    leaderboard.sort((a, b) => b.total_score - a.total_score);
    const headers = allChallenges.map(c => ({ id: c.id, title: c.title }));
    res.json({ success: true, labs: headers, leaderboard: leaderboard });
});

router.get('/history', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: "Not logged in" });
    if (process.env.SHOW_HISTORY !== 'true') return res.status(403).json({ error: "History disabled" });
    
    const cfg = getConfig();
    const submissions = db.prepare("SELECT id, lab_id, score, max_score, timestamp, details, type FROM submissions WHERE user_id = ? AND status = 'completed' ORDER BY id DESC").all(req.session.userId);
    
    const safeSubmissions = submissions.map(sub => {
        let showScore = true;
        let showDetails = true;
        let type = sub.type || 'lab';

        if (type === 'quiz') {
            const qCfg = (cfg.quizzes || []).find(q => q.id === sub.lab_id);
            showScore = qCfg ? (qCfg.show_score !== false) : true;
            showDetails = qCfg ? (qCfg.show_corrections !== false) : true;
        } else {
            const lCfg = (cfg.labs || []).find(l => l.id === sub.lab_id);
            showScore = lCfg ? (lCfg.show_score !== false) : true;
            showDetails = lCfg ? (lCfg.show_check_messages !== false) : true;
        }

        let details = [];
        try { details = JSON.parse(sub.details); } catch(e) {}
        
        let clientDetails = null;
        if (showDetails) {
            if (type === 'quiz') {
                clientDetails = details; 
            } else {
                clientDetails = details.map(item => ({ message: item.message, points: item.awarded, passed: item.passed }));
            }
        }
        
        return {
            id: sub.id,
            lab_id: sub.lab_id,
            type: type,
            score: showScore ? sub.score : null,
            max_score: showScore ? sub.max_score : null,
            timestamp: sub.timestamp,
            details: clientDetails
        };
    });
    res.json({ success: true, history: safeSubmissions });
});

module.exports = router;