const { getXmlValue } = require('./parser');
const CryptMD5 = require('cryptmd5');

function verifyType5(password, storedHash) {
    if (typeof storedHash !== 'string' || !storedHash.startsWith('$1$')) {
        return false;
    }

    const parts = storedHash.split('$');
    if (parts.length < 4 || !parts[2] || !parts[3]) {
        return false;
    }

    const salt = parts[2];
    try {
        const computed = CryptMD5.cryptMD5(password, salt);
        return computed === storedHash;
    } catch (e) {
        return false;
    }
}

function evaluateCondition(device, condition) {
    if (!device) return false;

    // Detect Negation
    let type = condition.type;
    let isNegated = false;

    if (type.endsWith('Not')) {
        isNegated = true;
        type = type.slice(0, -3); // Remove "Not" suffix
    }

    let result = false;

    // --- XML CHECKS ---
    if (type === 'XmlMatch') {
        const actual = getXmlValue(device.xmlRoot, condition.path);
        
        if (actual !== undefined && actual !== null) {
            result = String(actual).trim() === String(condition.value).trim();
        }
    }
    else if (type === 'XmlRegex') {
        const actual = getXmlValue(device.xmlRoot, condition.path);
        if (actual !== undefined && actual !== null) {
            try {
                const re = new RegExp(condition.value);
                result = re.test(String(actual));
            } catch (e) { result = false; }
        }
    }

    // --- CONFIG CHECKS (Standard) ---
    else if (['ConfigMatch', 'ConfigRegex'].includes(type)) {
        const sourceCfg = condition.source === 'startup' ? device.startup : device.running;
        let targetLines = [];
        
        if (!condition.context || condition.context === 'global') {
            targetLines = sourceCfg.global;
        } else {
            const searchCtx = condition.context.toLowerCase().replace(/\s/g, '');
            const blockKey = Object.keys(sourceCfg.blocks).find(k => k.toLowerCase().replace(/\s/g, '') === searchCtx);
            if (blockKey) targetLines = sourceCfg.blocks[blockKey];
        }

        // If lines exist, check them
        if (targetLines) {
            if (type === 'ConfigRegex') {
                try {
                    const regex = new RegExp(condition.value);
                    result = targetLines.some(l => regex.test(l));
                } catch (e) { result = false; }
            }
            else if (type === 'ConfigMatch') {
                result = targetLines.includes(condition.value);
            }
        }
    }

    // --- CONFIG CHECKS (Type 5 Password Verification) ---
    else if (type === 'Type5Match') {
        const sourceCfg = condition.source === 'startup' ? device.startup : device.running;
        
        // Passwords are typically stored in the global configuration scope
        let targetLines = sourceCfg.global || [];
        let hashToVerify = null;

        if (condition.mode === 'device') {
            // Looking for: enable secret 5 $1$salt$hash...
            const regex = /^enable\s+secret\s+5\s+(\$1\$.+)$/i;
            for (const line of targetLines) {
                const match = line.match(regex);
                if (match) {
                    hashToVerify = match[1];
                    break;
                }
            }
        } else if (condition.mode === 'user') {
            // Looking for: username <user> [privilege X] secret 5 $1$salt$hash...
            const escapedUser = (condition.username || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regex = new RegExp(`^username\\s+${escapedUser}\\s+.*secret\\s+5\\s+(\\$1\\$.+)$`, 'i');
            for (const line of targetLines) {
                const match = line.match(regex);
                if (match) {
                    hashToVerify = match[1];
                    break;
                }
            }
        }

        if (hashToVerify) {
            result = verifyType5(condition.password || '', hashToVerify);
        } else {
            result = false;
        }
    }

    // Return result (inverted if Negated)
    return isNegated ? !result : result;
}

module.exports = { evaluateCondition };