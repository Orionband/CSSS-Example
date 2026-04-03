const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

const question = (query) => new Promise(resolve => readline.question(query, resolve));
const askBool = async (query) => {
    let ans = await question(`${query} (y/n) [n]: `);
    return ans.trim().toLowerCase() === 'y' ? 'true' : 'false';
};

(async () => {
    const envFile = path.join(__dirname, '.env');
    const secret = crypto.randomBytes(64).toString('hex');

    let envContent = '';
    if (fs.existsSync(envFile)) {
        envContent = fs.readFileSync(envFile, 'utf-8');
    }

    console.log("=== CSSS Configuration Setup ===\n");

    const appTitle = await question('Application title (shown on login and dashboard) [CSSS ENGINE]: ');
    const retainPka = await askBool('Retain student .pka files on the server?');
    const retainXml = await askBool('Retain decompressed .xml grading files on the server?');
    const showLeaderboard = await askBool('Enable global leaderboard?');
    const showHistory = await askBool('Enable History tab for students?');

    const replaceOrAdd = (key, value) => {
        const regex = new RegExp(`^${key}=.*`, 'm');
        if (regex.test(envContent)) {
            envContent = envContent.replace(regex, `${key}=${value}`);
        } else {
            envContent += `\n${key}=${value}\n`;
        }
    };

    replaceOrAdd('SESSION_SECRET', secret);
    replaceOrAdd('NODE_ENV', 'production');
    replaceOrAdd('APP_TITLE', appTitle.trim() || 'CSSS ENGINE');
    replaceOrAdd('RETAIN_PKA', retainPka);
    replaceOrAdd('RETAIN_XML', retainXml);
    replaceOrAdd('SHOW_LEADERBOARD', showLeaderboard);
    replaceOrAdd('SHOW_HISTORY', showHistory);

    envContent = envContent.replace(/^MAX_UPLOAD_MB=.*\n?/gm, '');
    envContent = envContent.replace(/^MAX_XML_OUTPUT_MB=.*\n?/gm, '');

    envContent = envContent.replace(/\n\n+/g, '\n').trim() + '\n';
    fs.writeFileSync(envFile, envContent, 'utf-8');

    console.log('\n--- Configuration Saved to .env ---');
    console.log('SESSION_SECRET:   [Generated]');
    console.log('NODE_ENV:         production');
    console.log(`APP_TITLE:        ${appTitle.trim() || 'CSSS ENGINE'}`);
    console.log(`RETAIN_PKA:       ${retainPka}`);
    console.log(`RETAIN_XML:       ${retainXml}`);
    console.log(`SHOW_LEADERBOARD: ${showLeaderboard}`);
    console.log(`SHOW_HISTORY:     ${showHistory}`);
    
    readline.close();
})();