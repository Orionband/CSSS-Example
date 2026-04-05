const socket = io({ autoConnect: false }); 
let currentUser = null;
let availableChallenges = [];
let currentChallengeId = null;
let currentChallengeType = null;
let quizTimerInterval = null;
let labTimerInterval = null;
let quizMetadataCache = null; 
let csrfToken = null;

const quizView = document.getElementById('view-quiz');
['copy', 'paste', 'cut', 'contextmenu'].forEach(evt => {
    quizView.addEventListener(evt, e => {
        e.preventDefault();
        return false;
    });
});

function toggleAuth(mode) {
    document.getElementById('login-form').classList.toggle('hidden', mode !== 'login');
    document.getElementById('register-form').classList.toggle('hidden', mode !== 'register');
    document.getElementById('auth-error').innerText = '';
}

async function securePost(url, body = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    return fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
}

async function fetchCsrfToken() {
    try {
        const res = await fetch('/api/csrf-token');
        const data = await res.json();
        if (data.csrfToken) csrfToken = data.csrfToken;
    } catch (e) {
        console.error("Failed to fetch CSRF token");
    }
}

function applyBranding(options) {
    const main = options.app_title_main || 'CSSS';
    const full = options.app_title || 'CSSS ENGINE';

    const authTitle = document.getElementById('auth-title');
    authTitle.textContent = full;

    const navBrand = document.getElementById('nav-brand');
    navBrand.textContent = full;

    document.title = full;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

async function login() {
    const user = document.getElementById('l-user').value;
    const pass = document.getElementById('l-pass').value;
    const res = await securePost('/api/login', { username: user, password: pass });
    const data = await res.json();
    if(data.success) initApp(data.unique_id);
    else document.getElementById('auth-error').innerText = data.error;
}

async function register() {
    const user = document.getElementById('r-user').value;
    const email = document.getElementById('r-email').value;
    const pass = document.getElementById('r-pass').value;
    const res = await securePost('/api/register', { username: user, email: email, password: pass });
    const data = await res.json();
    if(data.success) initApp(data.unique_id);
    else document.getElementById('auth-error').innerText = data.error;
}

async function logout() {
    await securePost('/api/logout');
    csrfToken = null;
    location.reload();
}

function initApp(uid) {
    currentUser = uid;
    document.getElementById('loading-view').classList.add('hidden');
    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('app-view').classList.remove('hidden');
    document.getElementById('uid-display').innerText = uid;
    
    socket.disconnect(); 
    socket.connect();
    
    socket.once('connect', () => {
        socket.emit('authenticate', uid);
    });

    fetchCsrfToken().then(() => fetchConfig());
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-login-submit')?.addEventListener('click', login);
    document.getElementById('btn-register-submit')?.addEventListener('click', register);
    document.getElementById('link-show-register')?.addEventListener('click', () => toggleAuth('register'));
    document.getElementById('link-show-login')?.addEventListener('click', () => toggleAuth('login'));
    document.getElementById('btn-logout')?.addEventListener('click', logout);
    document.getElementById('btn-submit-quiz')?.addEventListener('click', submitQuiz);
    document.getElementById('upload-area-box')?.addEventListener('click', () => document.getElementById('f').click());
    document.getElementById('btn-close-history')?.addEventListener('click', closeHistory);

    fetchCsrfToken().then(() => {
        fetch('/api/me')
            .then(r => r.json())
            .then(data => {
                if(data.unique_id) initApp(data.unique_id);
                else {
                    document.getElementById('loading-view').classList.add('hidden');
                    document.getElementById('auth-view').classList.remove('hidden');
                    fetch('/api/config').then(r => r.json()).then(d => {
                        if (d.options) applyBranding(d.options);
                    }).catch(() => {});
                }
            })
            .catch(() => {
                document.getElementById('loading-view').classList.add('hidden');
                document.getElementById('auth-view').classList.remove('hidden');
                fetch('/api/config').then(r => r.json()).then(d => {
                    if (d.options) applyBranding(d.options);
                }).catch(() => {});
            });
    });
});

async function fetchConfig() {
    const res = await fetch('/api/config');
    const data = await res.json();
    availableChallenges = data.challenges;
    
    if (data.options) applyBranding(data.options);
    
    renderNav(data.options);
    if(availableChallenges.length > 0) switchTab(availableChallenges[0].id);
}

function renderNav(options) {
    const nav = document.getElementById('nav-links-container');
    nav.innerHTML = '';
    availableChallenges.forEach(ch => {
        const item = document.createElement('div');
        item.className = 'nav-item';
        item.id = 'nav-' + ch.id;
        const label = ch.type === 'quiz' ? '[QUIZ] ' : '[LAB] ';
        item.innerText = label + ch.title;
        item.onclick = () => switchTab(ch.id);
        nav.appendChild(item);
    });
    
    if (options.show_leaderboard) {
        const lb = document.createElement('div');
        lb.className = 'nav-item';
        lb.id = 'nav-leaderboard';
        lb.innerText = 'Leaderboard';
        lb.onclick = () => switchTab('leaderboard');
        nav.appendChild(lb);
    }
    
    if (options.show_history) {
        const hist = document.createElement('div');
        hist.className = 'nav-item';
        hist.id = 'nav-history';
        hist.innerText = 'History';
        hist.onclick = () => switchTab('history');
        nav.appendChild(hist);
    }
}

function switchTab(id) {
    document.getElementById('view-grader').classList.add('hidden');
    document.getElementById('view-quiz').classList.add('hidden');
    document.getElementById('view-history').classList.add('hidden');
    document.getElementById('view-leaderboard').classList.add('hidden');
    
    if (quizTimerInterval) clearInterval(quizTimerInterval);
    if (labTimerInterval) clearInterval(labTimerInterval);

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const activeNav = document.getElementById('nav-' + id);
    if(activeNav) activeNav.classList.add('active');

    if(id === 'history') {
        document.getElementById('view-history').classList.remove('hidden');
        loadHistory();
    } else if(id === 'leaderboard') {
        document.getElementById('view-leaderboard').classList.remove('hidden');
        loadLeaderboard();
    } else {
        currentChallengeId = id;
        const challenge = availableChallenges.find(c => c.id === id);
        if(challenge) {
            currentChallengeType = challenge.type;
            if (challenge.type === 'lab') {
                document.getElementById('view-grader').classList.remove('hidden');
                loadLabInfo(id);
            } else if (challenge.type === 'quiz') {
                document.getElementById('view-quiz').classList.remove('hidden');
                loadQuiz(id);
            }
        }
    }
}

// ===================== LAB START FLOW =====================

async function loadLabInfo(id) {
    document.getElementById('lab-start-screen').classList.remove('hidden');
    document.getElementById('lab-active-screen').classList.add('hidden');
    document.getElementById('report').classList.add('hidden');
    document.getElementById('progress-container').style.display = 'none';
    document.getElementById('status').innerText = '';

    const infoArea = document.getElementById('lab-info-area');
    infoArea.innerHTML = "<div style='text-align:center; padding:20px'>Loading...</div>";

    const res = await fetch(`/api/lab/${id}`);
    const data = await res.json();

    if (data.error) {
        infoArea.innerHTML = `<div class="error-msg">${escapeHtml(data.error)}</div>`;
        return;
    }

    document.getElementById('lab-title').innerText = data.title;

    let timeText = data.time_limit_minutes > 0 ? `${data.time_limit_minutes} Minutes` : "Unlimited";
    let attemptsText = data.max_submissions > 0 ? `${data.attempts_taken} / ${data.max_submissions}` : `${data.attempts_taken} (Unlimited)`;
    let pkaText = data.has_pka_file ? "Yes (available after starting)" : "None";

    if (data.session_active) {
        showLabActive(id, data);
        return;
    }

    infoArea.innerHTML = `
        <div class="quiz-start-screen">
            <div class="quiz-info-box">
                <div class="quiz-info-item"><span>Time Limit:</span> ${escapeHtml(timeText)}</div>
                <div class="quiz-info-item"><span>Attempts:</span> ${escapeHtml(attemptsText)}</div>
                <div class="quiz-info-item"><span>PKA provided:</span> ${escapeHtml(pkaText)}</div>
            </div>
            <br>
            <button id="btn-start-lab-dyn" data-id="${id}" style="width:auto; font-size:1.2rem; padding:15px 40px;">START LAB</button>
        </div>
    `;
    document.getElementById('btn-start-lab-dyn').addEventListener('click', (e) => startLabSession(e.target.dataset.id));
}

async function startLabSession(id) {
    const res = await securePost(`/api/lab/${id}/start`, {});
    const data = await res.json();

    if (data.error) {
        alert(data.error);
        loadLabInfo(id);
        return;
    }

    showLabActive(id, data);
}

function showLabActive(id, data) {
    document.getElementById('lab-start-screen').classList.add('hidden');
    document.getElementById('lab-active-screen').classList.remove('hidden');
    document.getElementById('report').classList.add('hidden');
    document.getElementById('progress-container').style.display = 'none';
    document.getElementById('status').innerText = '';

    const challenge = availableChallenges.find(c => c.id === id);
    document.getElementById('lab-active-title').innerText = challenge ? challenge.title : id;

    const dlArea = document.getElementById('lab-download-area');
    if (data.has_pka_file) {
        dlArea.classList.remove('hidden');
        const dlBtn = document.getElementById('lab-download-btn');
        dlBtn.href = `/api/lab/${id}/download`;
        dlBtn.setAttribute('download', '');
    } else {
        dlArea.classList.add('hidden');
    }

    const timerDiv = document.getElementById('lab-timer');
    if (labTimerInterval) clearInterval(labTimerInterval);

    if (data.time_remaining_seconds !== null && data.time_remaining_seconds !== undefined) {
        const targetEndTime = Date.now() + (data.time_remaining_seconds * 1000);
        const updateTimer = () => {
            const remaining = Math.max(0, Math.floor((targetEndTime - Date.now()) / 1000));
            const m = Math.floor(remaining / 60);
            const s = remaining % 60;
            timerDiv.innerText = `${m}:${s < 10 ? '0' : ''}${s}`;

            if (remaining <= 0) {
                clearInterval(labTimerInterval);
                timerDiv.innerText = "TIME'S UP";
                timerDiv.style.color = '#f44747';
                alert("Time's up! You can no longer submit for this lab session.");
                const uploadArea = document.querySelector('#lab-active-screen .upload-area');
                if (uploadArea) {
                    uploadArea.style.pointerEvents = 'none';
                    uploadArea.style.opacity = '0.4';
                }
            }
        };
        updateTimer();
        labTimerInterval = setInterval(updateTimer, 1000);
    } else {
        timerDiv.innerText = '';
    }
}

// ===================== QUIZ FLOW =====================

async function loadQuiz(id) {
    document.getElementById('quiz-result').classList.add('hidden');
    const area = document.getElementById('quiz-questions-area');
    area.innerHTML = "<div style='text-align:center; padding:20px'>Loading Info...</div>";
    
    const res = await fetch(`/api/quiz/${id}`);
    const data = await res.json();
    
    if (data.error) {
        area.innerHTML = `<div class="error-msg">${escapeHtml(data.error)}</div>`;
        document.getElementById('btn-submit-quiz').style.display = 'none';
        document.getElementById('quiz-title').innerText = "Quiz Unavailable";
        return;
    }

    quizMetadataCache = data; 
    document.getElementById('quiz-title').innerText = data.title;
    document.getElementById('btn-submit-quiz').style.display = 'none';
    document.getElementById('quiz-timer').innerText = '';

    let timeText = data.time_limit > 0 ? `${data.time_limit} Minutes` : "Unlimited";
    let attemptsText = data.max_attempts > 0 ? `${data.attempts_taken} / ${data.max_attempts}` : `${data.attempts_taken} (Unlimited)`;
    
    area.innerHTML = `
        <div class="quiz-start-screen">
            <div class="quiz-info-box">
                <div class="quiz-info-item"><span>Time Limit:</span> ${escapeHtml(timeText)}</div>
                <div class="quiz-info-item"><span>Attempts:</span> ${escapeHtml(attemptsText)}</div>
                <div class="quiz-info-item"><span>Questions:</span> ${escapeHtml(String(data.question_count))}</div>
            </div>
            <br>
            <button id="btn-start-quiz-dyn" style="width:auto; font-size:1.2rem; padding:15px 40px;">START QUIZ</button>
        </div>
    `;
    document.getElementById('btn-start-quiz-dyn').addEventListener('click', startQuizSession);
}

async function startQuizSession() {
    if(!currentChallengeId) return;
    
    const area = document.getElementById('quiz-questions-area');
    area.innerHTML = "Fetching questions...";

    const res = await securePost(`/api/quiz/${currentChallengeId}/start`, {});
    const data = await res.json();

    if(data.error) {
        alert(data.error);
        loadQuiz(currentChallengeId); 
        return;
    }

    area.innerHTML = '';
    document.getElementById('btn-submit-quiz').style.display = 'block';

    data.questions.forEach((q, idx) => {
        const card = document.createElement('div');
        card.className = 'quiz-question-card';
        card.dataset.type = q.type;
        card.innerHTML = `<div class="quiz-q-text">${idx+1}. ${escapeHtml(q.text)}</div>`;
        
        if (q.image) {
            const img = document.createElement('img');
            img.src = `/api/quiz/asset/image/${q.image}`;
            img.style.maxWidth = "100%";
            card.appendChild(img);
        }

        if (q.pka) {
            const pkaLink = document.createElement('a');
            pkaLink.href = `/api/quiz/asset/pka/${q.pka}`;
            pkaLink.download = q.pka;
            pkaLink.className = 'lab-download-link';
            pkaLink.innerHTML = `[ DOWNLOAD ] Packet Tracer Exhibit`;
            pkaLink.style.display = 'inline-block';
            pkaLink.style.marginTop = '10px';
            pkaLink.style.marginBottom = '10px';
            card.appendChild(pkaLink);
        }

        const optsDiv = document.createElement('div');
        optsDiv.className = 'quiz-options';

        if (q.type === 'text') {
            const inp = document.createElement('input');
            inp.type = 'text';
            inp.className = 'quiz-text-input';
            inp.name = `q_${idx}`;
            optsDiv.appendChild(inp);
        } 
        else if (q.type === 'matching') {
            const matchContainer = document.createElement('div');
            matchContainer.className = 'matching-container';
            
            const colLeft = document.createElement('div');
            colLeft.className = 'matching-col';
            q.leftItems.forEach(item => {
                const row = document.createElement('div');
                row.className = 'match-item';
                row.innerHTML = `<div class="match-left">${escapeHtml(item.text)}</div>`;
                
                const dropZone = document.createElement('div');
                dropZone.className = 'drop-zone';
                dropZone.dataset.leftId = item.id;
                
                dropZone.ondragover = (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); };
                dropZone.ondragleave = (e) => { dropZone.classList.remove('drag-over'); };
                dropZone.ondrop = (e) => {
                    e.preventDefault();
                    dropZone.classList.remove('drag-over');
                    const optId = e.dataTransfer.getData('text/plain');
                    const draggedElement = document.getElementById(optId);
                    if (draggedElement) {
                        dropZone.innerHTML = ''; 
                        dropZone.appendChild(draggedElement);
                    }
                };
                row.appendChild(dropZone);
                colLeft.appendChild(row);
            });

            const colRight = document.createElement('div');
            colRight.className = 'matching-col';
            const pool = document.createElement('div');
            pool.className = 'drop-zone pool-zone';
            pool.style.minHeight = '100px';
            pool.style.flexWrap = 'wrap';
            pool.style.gap = '10px';
            pool.ondragover = (e) => e.preventDefault();
            pool.ondrop = (e) => {
                e.preventDefault();
                const optId = e.dataTransfer.getData('text/plain');
                const draggedElement = document.getElementById(optId);
                if (draggedElement) pool.appendChild(draggedElement);
            };

            q.rightOptions.forEach(opt => {
                const dragItem = document.createElement('div');
                dragItem.className = 'draggable-item';
                dragItem.draggable = true;
                dragItem.id = `opt-${idx}-${opt.id}`;
                dragItem.dataset.val = opt.id;
                dragItem.innerText = opt.text;
                dragItem.ondragstart = (e) => { e.dataTransfer.setData('text/plain', dragItem.id); };
                pool.appendChild(dragItem);
            });
            colRight.appendChild(pool);

            matchContainer.appendChild(colLeft);
            matchContainer.appendChild(colRight);
            optsDiv.appendChild(matchContainer);
        }
        else {
            q.answers.forEach(ans => {
                const label = document.createElement('label');
                const inp = document.createElement('input');
                inp.type = q.type;
                inp.name = `q_${idx}`;
                inp.value = ans.id;
                
                label.appendChild(inp);
                label.appendChild(document.createTextNode(ans.text));
                optsDiv.appendChild(label);
            });
        }
        card.appendChild(optsDiv);
        area.appendChild(card);
    });

    if (quizMetadataCache.time_limit > 0 && data.time_remaining_seconds !== undefined) {
        const targetEndTime = Date.now() + (data.time_remaining_seconds * 1000);
        const timerDiv = document.getElementById('quiz-timer');
        const updateTimer = () => {
            const remaining = Math.max(0, Math.floor((targetEndTime - Date.now()) / 1000));
            const m = Math.floor(remaining / 60);
            const s = remaining % 60;
            timerDiv.innerText = `${m}:${s < 10 ? '0' : ''}${s}`;
            if (remaining <= 0) {
                clearInterval(quizTimerInterval);
                alert("Time's up! Submitting...");
                submitQuiz();
            }
        };
        updateTimer();
        quizTimerInterval = setInterval(updateTimer, 1000);
    }
}

async function submitQuiz() {
    if (quizTimerInterval) clearInterval(quizTimerInterval);
    const answers = {};
    const area = document.getElementById('quiz-questions-area');
    const cards = area.getElementsByClassName('quiz-question-card');

    for (let i = 0; i < cards.length; i++) {
        const type = cards[i].dataset.type;
        
        if (type === 'text') {
            const textInput = cards[i].querySelector('input[type="text"]');
            if (textInput) answers[i] = textInput.value;
        } 
        else if (type === 'matching') {
            const matches = {};
            const rows = cards[i].querySelectorAll('.match-item');
            rows.forEach(row => {
                const zone = row.querySelector('.drop-zone');
                const leftId = zone.dataset.leftId;
                const child = zone.querySelector('.draggable-item');
                if (child) {
                    matches[leftId] = child.dataset.val;
                }
            });
            answers[i] = matches;
        }
        else {
            const inputs = cards[i].querySelectorAll('input:checked');
            if (inputs.length === 1 && type === 'radio') {
                answers[i] = inputs[0].value;
            } else if (inputs.length > 0) {
                answers[i] = Array.from(inputs).map(inp => inp.value);
            }
        }
    }

    const res = await securePost(`/api/quiz/${currentChallengeId}/submit`, { answers });
    const result = await res.json();
    
    if (result.error) {
        alert(result.error);
        return;
    }

    const allInputs = area.querySelectorAll('input');
    allInputs.forEach(inp => inp.disabled = true);

    const draggables = area.querySelectorAll('.draggable-item');
    draggables.forEach(d => {
        d.removeAttribute('draggable');
        d.ondragstart = null;
        d.style.cursor = 'not-allowed';
        d.style.opacity = '0.7';
    });

    const dropZones = area.querySelectorAll('.drop-zone');
    dropZones.forEach(dz => {
        dz.ondrop = null;
        dz.ondragover = null;
        dz.ondragleave = null;
    });

    document.getElementById('btn-submit-quiz').style.display = 'none';
    const resDiv = document.getElementById('quiz-result');
    resDiv.classList.remove('hidden');
    
    if (result.score !== null) {
        document.getElementById('quiz-score-display').innerText = `Score: ${result.score} / ${result.max_score}`;
    } else {
        document.getElementById('quiz-score-display').innerText = "Score Hidden";
    }

    const feedList = document.getElementById('quiz-feedback-list');
    feedList.innerHTML = '';
    
    if (result.breakdown) {
        result.breakdown.forEach(item => {
            const div = document.createElement('div');
            div.className = `quiz-feedback ${item.correct ? 'correct' : 'missed'}`;
            div.innerHTML = `<strong>${escapeHtml(item.message)}</strong>: ${item.correct ? 'Correct' : 'Missed'}<br><small>Explanation: ${escapeHtml(item.explanation)}</small>`;
            feedList.appendChild(div);
        });
    } else {
        feedList.innerHTML = "<em>Corrections hidden by instructor.</em>";
    }
    window.scrollTo(0,0);
}

// ===================== LEADERBOARD & HISTORY =====================

async function loadLeaderboard() {
    const res = await fetch('/api/leaderboard');
    const data = await res.json();
    if (data.error) {
        alert(data.error);
        return;
    }
    
    const theadRow = document.querySelector('#lb-table thead tr');
    theadRow.innerHTML = '<th>Rank</th><th>User</th>';
    data.labs.forEach(l => {
        const th = document.createElement('th');
        th.innerText = l.title;
        theadRow.appendChild(th);
    });
    const thTotal = document.createElement('th'); thTotal.innerText = 'Total';
    theadRow.appendChild(thTotal);
    const tbody = document.getElementById('lb-body');
    tbody.innerHTML = '';
    data.leaderboard.forEach((entry, index) => {
        const tr = document.createElement('tr');
        let html = `<td>#${index + 1}</td><td>${escapeHtml(entry.username)}</td>`;
        data.labs.forEach(l => {
            const score = entry.scores[l.id] || 0;
            html += `<td style="color:#b8b8b8">${score}</td>`;
        });
        html += `<td style="color:var(--accent); font-weight:bold">${entry.total_score}</td>`;
        tr.innerHTML = html;
        tbody.appendChild(tr);
    });
}

async function loadHistory() {
    const res = await fetch('/api/history');
    const data = await res.json();
    
    if (data.error) {
        alert(data.error);
        return;
    }

    const list = document.getElementById('history-list');
    if(!data.history || data.history.length === 0) {
        list.innerHTML = "<div style='text-align:center; padding:20px; color:#888'>No submissions yet.</div>";
        return;
    }
    list.innerHTML = '';
    data.history.forEach(sub => {
        const item = document.createElement('div');
        item.className = 'history-row';
        const date = new Date(sub.timestamp).toLocaleString();
        item.addEventListener('click', () => showHistoryDetail(sub));
        const challenge = availableChallenges.find(c => c.id === sub.lab_id);
        const title = challenge ? challenge.title : sub.lab_id;
        const scoreText = (sub.score !== null) ? `${sub.score} / ${sub.max_score}` : "Hidden";
        const typeLabel = sub.type === 'quiz' ? '<span class="hist-type type-quiz">QUIZ</span>' : '<span class="hist-type type-lab">LAB</span>';
        item.innerHTML = `<div><div style="font-weight:bold; color:#fff">${typeLabel} ${escapeHtml(title)}</div><div class="hist-date">${date}</div></div><div class="hist-score">${scoreText}</div>`;
        list.appendChild(item);
    });
}

// Reusable nested rendering logic for Lab Feedback
function renderLabResults(container, breakdown) {
    container.innerHTML = '';
    if (!breakdown || breakdown.length === 0) {
        container.innerHTML = "<div style='text-align:center; padding:20px; color:#888'>No feedback available.</div>";
        return;
    }

    const grouped = {};
    breakdown.forEach(item => {
        const dev = item.device || 'Unknown Device';
        const ctx = item.context || 'global';
        if (!grouped[dev]) grouped[dev] = {};
        if (!grouped[dev][ctx]) grouped[dev][ctx] = [];
        grouped[dev][ctx].push(item);
    });

    for (const dev of Object.keys(grouped).sort()) {
        const devDiv = document.createElement('div');
        devDiv.className = 'result-group';
        
        const devHeader = document.createElement('div');
        devHeader.className = 'result-group-header expanded';
        devHeader.innerHTML = `<span class="indicator">▶</span> ${escapeHtml(dev)}`;
        
        const devContent = document.createElement('div');
        devContent.className = 'result-group-content';
        
        devHeader.onclick = () => {
            devHeader.classList.toggle('expanded');
            devContent.classList.toggle('hidden');
        };

        for (const ctx of Object.keys(grouped[dev]).sort()) {
            const ctxDiv = document.createElement('div');
            ctxDiv.className = 'result-subgroup';
            
            const ctxHeader = document.createElement('div');
            ctxHeader.className = 'result-subgroup-header expanded';
            ctxHeader.innerHTML = `<span class="indicator">▶</span> ${escapeHtml(ctx)}`;
            
            const ctxContent = document.createElement('div');
            ctxContent.className = 'result-subgroup-content';
            
            ctxHeader.onclick = () => {
                ctxHeader.classList.toggle('expanded');
                ctxContent.classList.toggle('hidden');
            };

            grouped[dev][ctx].forEach(c => {
                const row = document.createElement('div');
                if (c.passed !== false) {
                    row.className = 'check-item ' + (c.points >= 0 ? 'gain' : 'penalty');
                    row.innerHTML = `<span>${escapeHtml(c.message)}</span><span class="pts">${c.points > 0 ? '+'+c.points : c.points}</span>`;
                } else {
                    row.className = 'check-item missed';
                    row.innerHTML = `<span>${escapeHtml(c.message)}</span><span class="pts" style="color: #4da6ff">${c.points}</span>`;
                }
                ctxContent.appendChild(row);
            });

            ctxDiv.appendChild(ctxHeader);
            ctxDiv.appendChild(ctxContent);
            devContent.appendChild(ctxDiv);
        }
        
        devDiv.appendChild(devHeader);
        devDiv.appendChild(devContent);
        container.appendChild(devDiv);
    }
}

function showHistoryDetail(sub) {
    document.getElementById('history-list').parentElement.classList.add('hidden');
    document.getElementById('history-detail').classList.remove('hidden');
    document.getElementById('hist-date').innerText = new Date(sub.timestamp).toLocaleString();
    const challenge = availableChallenges.find(c => c.id === sub.lab_id);
    document.getElementById('hist-lab').innerText = challenge ? challenge.title : sub.lab_id;
    document.getElementById('hist-score').innerText = (sub.score !== null) ? `${sub.score} / ${sub.max_score}` : "Hidden";
    
    const cont = document.getElementById('hist-checks');
    cont.innerHTML = '';
    
    if (sub.details === null) {
        cont.innerHTML = "<div style='text-align:center; color:#888'>Details hidden.</div>";
    } else {
        if (sub.type === 'quiz') {
            sub.details.forEach(item => {
                const row = document.createElement('div');
                row.className = `quiz-feedback ${item.correct ? 'correct' : 'missed'}`;
                row.innerHTML = `<strong>${escapeHtml(item.message)}</strong>: ${item.correct ? 'Correct' : 'Missed'}`;
                cont.appendChild(row);
            });
        } else {
            renderLabResults(cont, sub.details);
        }
    }
}

function closeHistory() {
    document.getElementById('history-detail').classList.add('hidden');
    document.getElementById('history-list').parentElement.classList.remove('hidden');
}

// ===================== FILE UPLOAD =====================

const fileInput = document.getElementById('f');
const progressBar = document.getElementById('progress-bar');
const statusText = document.getElementById('status');

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if(!file) return;
    if(currentChallengeType !== 'lab') return;
    document.getElementById('report').classList.add('hidden');
    document.getElementById('progress-container').style.display = 'block';
    progressBar.style.width = '0%';
    progressBar.style.background = 'var(--accent)';
    statusText.innerText = "Uploading...";
    fileInput.value = ''; 
    const reader = new FileReader();
    reader.onload = (evt) => {
        socket.emit('upload_file', { 
            fileData: evt.target.result, 
            labId: currentChallengeId,
            _csrf: csrfToken
        });
        statusText.innerText = "Queued...";
    };
    reader.readAsArrayBuffer(file);
});

socket.on('progress', (d) => {
    let pct = parseFloat(d.percent) || 0;
    progressBar.style.width = pct + '%';
    statusText.innerText = `${d.stage} (${Math.round(pct)}%)`;
});

socket.on('result', (data) => {
    progressBar.style.width = '100%';
    statusText.innerText = "Done";
    const checksList = document.getElementById('checks-list');
    const scoreBox = document.getElementById('final-score');
    checksList.innerHTML = '';
    document.getElementById('report').classList.remove('hidden');
    
    if (data.show_score) scoreBox.innerText = `${data.total} / ${data.max}`;
    else scoreBox.innerText = "Hidden";
    
    if (data.clientBreakdown === null) {
        checksList.innerHTML = "<div style='text-align:center; color:#888'>Feedback hidden.</div>";
    } else {
        renderLabResults(checksList, data.clientBreakdown);
    }
});

socket.on('err', (msg) => {
    statusText.innerText = "Error: " + msg;
    progressBar.style.background = '#f44747';
});