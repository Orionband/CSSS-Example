const Database = require('better-sqlite3');
const readline = require('readline');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'grader.db');

if (!fs.existsSync(dbPath)) {
  console.error('grader.db not found in this directory.');
  process.exit(1);
}

function backupDb() {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = `${dbPath}.bak.${stamp}`;
  fs.copyFileSync(dbPath, dest);
  console.log(`Backup created: ${path.basename(dest)}`);
}

const db = new Database(dbPath, { readonly: false });
console.log('Opened grader.db');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(resolve =>
  rl.question(q, answer => resolve((answer === undefined || answer === null) ? '' : String(answer).trim()))
);

function listTables() {
  return db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(r => r.name);
}

function prettyPrintRows(rows) {
  if (!rows || !rows.length) {
    console.log('(no rows)');
    return;
  }
  console.table(rows.map(r => {
    const out = { ...r };
    if ('password' in out) out.password = '***bcrypt***';
    if ('details' in out && out.details) {
      try {
        out.details = JSON.stringify(JSON.parse(out.details), null, 2);
      } catch {
        // leave as-is if not JSON
      }
    }
    return out;
  }));
}

async function viewUsers() {
  const rows = db.prepare('SELECT rowid, * FROM users ORDER BY id').all();
  prettyPrintRows(rows);
}

async function viewSubmissions() {
  const rows = db.prepare('SELECT rowid, * FROM submissions ORDER BY id DESC').all();
  prettyPrintRows(rows);
}

// find user by numeric id or by username (returns full row including id)
function findUserByIdOrUsername(key) {
  if (!key) return null;
  if (/^\d+$/.test(key)) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(Number(key));
  } else {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(key);
  }
}

// return array of { table, from, to, on_update, on_delete }
function getReferencingForeignKeys() {
  const tables = listTables();
  const refs = [];
  for (const t of tables) {
    try {
      const fks = db.prepare(`PRAGMA foreign_key_list("${t}")`).all();
      for (const fk of fks) {
        if (fk.table === 'users') {
          refs.push({
            table: t,
            from: fk.from,
            to: fk.to,
            on_update: fk.on_update,
            on_delete: fk.on_delete
          });
        }
      }
    } catch (e) {
      // ignore tables that fail
    }
  }
  return refs;
}

async function deleteUser() {
  const key = await ask('Enter user id or username to delete: ');
  const user = findUserByIdOrUsername(key);
  if (!user) {
    console.log('User not found.');
    return;
  }

  console.log('User found:');
  console.table([ { ...user, password: '***bcrypt***' } ]);

  const refs = getReferencingForeignKeys();
  if (refs.length === 0) {
    console.log('No foreign-key references to users found. Safe to delete.');
    const confirm0 = await ask('Type YES to DELETE this user: ');
    if (confirm0 !== 'YES') { console.log('Aborted.'); return; }
    backupDb();
    try {
      const info = db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      console.log(`Deleted. Rows affected: ${info.changes}`);
    } catch (err) {
      console.error('Error deleting user:', err.message);
    }
    return;
  }

  console.log('\nFound foreign-key references to users:');
  for (const r of refs) {
    const cnt = db.prepare(`SELECT COUNT(1) AS c FROM "${r.table}" WHERE "${r.from}" = ?`).get(user.id).c;
    console.log(`- ${r.table}.${r.from} -> users.${r.to} : ${cnt} row(s)`);
    if (cnt > 0) {
      const sample = db.prepare(`SELECT rowid, * FROM "${r.table}" WHERE "${r.from}" = ? LIMIT 10`).all(user.id);
      console.log(`  sample rows (up to 10):`);
      console.table(sample);
    }
  }

  console.log('\nChoose action:');
  console.log('1) DELETE dependent rows in referencing tables, then DELETE user (recommended)');
  console.log('2) SET FK columns to NULL in referencing tables (only if those FK columns allow NULL), then DELETE user');
  console.log('3) FORCE DELETE user by temporarily disabling foreign keys (not recommended a_" leaves orphans)');
  console.log('4) Abort');

  const choice = await ask('Choose 1/2/3/4: ');

  if (!['1','2','3'].includes(choice)) {
    console.log('Aborted.');
    return;
  }

  backupDb();

  const tx = db.transaction((actionChoice) => {
    if (actionChoice === '1') {
      for (const r of refs) {
        const info = db.prepare(`DELETE FROM "${r.table}" WHERE "${r.from}" = ?`).run(user.id);
        console.log(`Deleted ${info.changes} row(s) from ${r.table}`);
      }
      const infoUser = db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      console.log(`Deleted user rows: ${infoUser.changes}`);
    } else if (actionChoice === '2') {
      for (const r of refs) {
        const cols = db.prepare(`PRAGMA table_info("${r.table}")`).all();
        const colInfo = cols.find(c => c.name === r.from);
        if (!colInfo) throw new Error(`Column ${r.from} not found on ${r.table}`);
        if (colInfo.notnull === 1) {
          throw new Error(`Column ${r.table}.${r.from} is NOT NULL a_" cannot set to NULL automatically. Canceling.`);
        }
      }
      for (const r of refs) {
        const info = db.prepare(`UPDATE "${r.table}" SET "${r.from}" = NULL WHERE "${r.from}" = ?`).run(user.id);
        console.log(`Updated ${info.changes} row(s) in ${r.table} (set ${r.from}=NULL)`);
      }
      const infoUser = db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      console.log(`Deleted user rows: ${infoUser.changes}`);
    } else if (actionChoice === '3') {
      db.exec('PRAGMA foreign_keys = OFF;');
      for (const r of refs) {
        const cnt = db.prepare(`SELECT COUNT(1) AS c FROM "${r.table}" WHERE "${r.from}" = ?`).get(user.id).c;
        console.log(`(force) ${cnt} dependent row(s) exist in ${r.table}`);
      }
      const infoUser = db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      console.log(`Deleted user rows (force): ${infoUser.changes}`);
      db.exec('PRAGMA foreign_keys = ON;');
    }
  });

  try {
    tx(choice);
    console.log('Operation completed.');
  } catch (err) {
    console.error('Operation failed:', err.message);
    console.log('No changes were committed.');
  }
}

function genRandomPassword(len = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

async function resetPassword() {
  const key = await ask('Enter user id or username to reset password: ');
  const user = findUserByIdOrUsername(key);
  if (!user) {
    console.log('User not found.');
    return;
  }
  console.log('User found:');
  console.table([ { ...user, password: '***bcrypt***' } ]);

  let pw = await ask('Enter new password (leave empty to auto-generate): ');
  if (!pw) {
    pw = genRandomPassword();
    console.log('Generated password:', pw);
  }
  const rounds = 10;
  const hash = bcrypt.hashSync(pw, rounds);
  backupDb();
  const info = db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
  console.log(`Password updated. Rows affected: ${info.changes}`);
}

async function wipeSubmissions() {
  const key = await ask('Enter user id or username whose submissions you want to wipe: ');
  const user = findUserByIdOrUsername(key);
  if (!user) {
    console.log('User not found.');
    return;
  }

  const count = db.prepare('SELECT COUNT(1) AS c FROM submissions WHERE user_id = ?').get(user.id).c;
  console.log(`User: ${user.username} (id=${user.id}). Submissions count: ${count}`);

  if (count === 0) {
    const confirmEmpty = await ask('No submissions found. Type YES to delete nothing and return, or anything else to abort: ');
    if (confirmEmpty === 'YES') {
      console.log('No-op. Returning.');
      return;
    } else {
      console.log('Aborted.');
      return;
    }
  }

  const sample = db.prepare('SELECT rowid, * FROM submissions WHERE user_id = ? ORDER BY id DESC LIMIT 10').all(user.id);
  console.log('Sample submissions (up to 10):');
  console.table(sample);

  const confirm = await ask(`This will DELETE ${count} submission(s) for user ${user.username} (id=${user.id}). Type WIPE to confirm: `);
  if (confirm !== 'WIPE') {
    console.log('Aborted.');
    return;
  }

  backupDb();
  try {
    const info = db.prepare('DELETE FROM submissions WHERE user_id = ?').run(user.id);
    console.log(`Deleted ${info.changes} submission(s) for user ${user.username} (id=${user.id}).`);
  } catch (err) {
    console.error('Error wiping submissions:', err.message);
  }
}

async function runPlainSql() {
  const sql = await ask('Enter SQL (single line). Use semi-colon to separate statements: ');
  if (!sql) return;
  const isSelect = /^\s*(select|pragma|with)/i.test(sql);
  if (!isSelect) {
    const confirm = await ask('Non-SELECT statement detected. Type YES to run: ');
    if (confirm !== 'YES') {
      console.log('Aborted.');
      return;
    }
    backupDb();
    try {
      const info = db.prepare(sql).run();
      console.log('OK. Result:', info);
    } catch (err) {
      console.error('Error:', err.message);
    }
  } else {
    try {
      const rows = db.prepare(sql).all();
      prettyPrintRows(rows);
    } catch (err) {
      console.error('Error:', err.message);
    }
  }
}

async function createUser() {
    const username = await ask('Enter new username: ');
    if (!username) return console.log("Aborted: Username required.");
    
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return console.log("Aborted: Username already exists.");

    const email = await ask('Enter new email: ');
    if (!email) return console.log("Aborted: Email required.");

    let pw = await ask('Enter password (leave empty to auto-generate): ');
    if (!pw) {
        pw = genRandomPassword();
        console.log('Generated password:', pw);
    }

    const uid = crypto.randomBytes(6).toString('hex');
    const hash = bcrypt.hashSync(pw, 10);

    backupDb();
    try {
        const info = db.prepare('INSERT INTO users (username, email, password, unique_id) VALUES (?, ?, ?, ?)').run(username, email, hash, uid);
        console.log(`User created successfully. ID: ${info.lastInsertRowid}, Unique_ID: ${uid}`);
    } catch (err) {
        console.error('Error creating user:', err.message);
    }
}

async function deleteSpecificSubmission() {
    const subId = await ask('Enter Submission ID to delete: ');
    if (!subId || isNaN(subId)) return console.log("Aborted: Invalid ID.");

    const sub = db.prepare('SELECT * FROM submissions WHERE id = ?').get(Number(subId));
    if (!sub) return console.log("Submission not found.");

    console.log("Submission found:");
    prettyPrintRows([sub]);

    const confirm = await ask(`Type DELETE to permanently remove submission #${subId}: `);
    if (confirm !== 'DELETE') return console.log("Aborted.");

    backupDb();
    try {
        const info = db.prepare('DELETE FROM submissions WHERE id = ?').run(sub.id);
        console.log(`Deleted ${info.changes} submission(s).`);
    } catch (err) {
        console.error('Error deleting submission:', err.message);
    }
}

async function mainMenu() {
  while (true) {
    console.log('\n=== Grader DB Tool ===');
    console.log('1) View users');
    console.log('2) View submissions');
    console.log('3) Create new user');
    console.log('4) Delete user (by id or username)');
    console.log('5) Reset user password (bcrypt 10 rounds)');
    console.log('6) Wipe ALL submissions for a specific user');
    console.log('7) Delete specific submission by ID');
    console.log('8) Run plain SQL');
    console.log('9) List tables');
    console.log('0) Exit');

    const choice = await ask('Choose (0-9): ');
    if (choice === '1') await viewUsers();
    else if (choice === '2') await viewSubmissions();
    else if (choice === '3') await createUser();
    else if (choice === '4') await deleteUser();
    else if (choice === '5') await resetPassword();
    else if (choice === '6') await wipeSubmissions();
    else if (choice === '7') await deleteSpecificSubmission();
    else if (choice === '8') await runPlainSql();
    else if (choice === '9') console.log('Tables:', listTables().join(', '));
    else if (choice === '0') break;
    else console.log('Invalid option.');
  }
  rl.close();
  db.close();
  console.log('Done.');
}

mainMenu().catch(err => {
  console.error(err);
  db.close();
  process.exit(1);
});