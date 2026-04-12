const fs = require('fs');
const toml = require('toml');
const path = require('path');

let config = { labs: [], quizzes: [] };
let rawConfig = ""; 

function reloadConfig() {
    try {
        // Load Lab Config
        const labPath = path.resolve(__dirname, '../lab.conf');
        if (fs.existsSync(labPath)) {
            rawConfig = fs.readFileSync(labPath, 'utf-8');
            if (rawConfig.charCodeAt(0) === 0xFEFF) { rawConfig = rawConfig.slice(1); }
            const parsedLab = toml.parse(rawConfig);
            config.labs = parsedLab.labs || [];
        }

        // Load Quiz Config
        const quizPath = path.resolve(__dirname, '../quiz.conf');
        if (fs.existsSync(quizPath)) {
            let quizRaw = fs.readFileSync(quizPath, 'utf-8');
            if (quizRaw.charCodeAt(0) === 0xFEFF) { quizRaw = quizRaw.slice(1); }
            const parsedQuiz = toml.parse(quizRaw);
            config.quizzes = parsedQuiz.quizzes || [];
        }

        console.log(`CSSS Config loaded. ${config.labs.length} Labs, ${config.quizzes.length} Quizzes.`);
    } catch (e) {
        console.warn("WARNING: Config error.");
        console.error(`   Details: ${e.message}`);
    }
}

function isWindowOpen(challenge) {
    if (!challenge) return true;
    
    // If no competition window dates are set, it is always open.
    if (!challenge.comp_start && !challenge.comp_end) return true;
    
    const now = Date.now();
    
    if (challenge.comp_start) {
        const startTime = new Date(challenge.comp_start).getTime();
        if (!isNaN(startTime) && now < startTime) return false;
    }
    
    if (challenge.comp_end) {
        const endTime = new Date(challenge.comp_end).getTime();
        if (!isNaN(endTime) && now > endTime) return false;
    }
    
    return true;
}

reloadConfig();

module.exports = { 
    getConfig: () => config, 
    getRawConfig: () => rawConfig, 
    isWindowOpen 
};