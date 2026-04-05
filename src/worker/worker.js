const { parentPort, workerData } = require('worker_threads');
const zlib = require('zlib');
const toml = require('toml');
const xml2js = require('xml2js');
const { xor, cmac, decryptCTR } = require('./crypto');
const { parseCiscoConfig } = require('./parser');
const { evaluateCondition } = require('./grading');

(async () => {
    try {
        const { fileData, configData, labId, maxXmlMb } = workerData;
        const inputBuffer = Buffer.from(fileData);
        const totalBytes = inputBuffer.length;
        const safeTotal = totalBytes > 0 ? totalBytes : 1;
        
        const report = (stage, pct) => {
            const safePct = (typeof pct === 'number' && !isNaN(pct)) ? pct : 0;
            parentPort.postMessage({ type: 'progress', stage, percent: safePct });
        };

        let finalXML = "";
        
        if (inputBuffer.subarray(0, 5).toString() === "<?xml") {
            report("Reading XML", 50);
            finalXML = inputBuffer.toString();
        } else {
            const key = Buffer.alloc(16, 137);
            const iv = Buffer.alloc(16, 16);
            
            const s1 = Buffer.allocUnsafe(totalBytes);
            const updateInterval = Math.floor(safeTotal / 10);
            
            report("Deobfuscating", 0);
            for (let i = 0; i < totalBytes; i++) {
                s1[i] = (inputBuffer[totalBytes - 1 - i] ^ ((totalBytes - (i * totalBytes)) | 0)) & 0xFF;
                if (i % updateInterval === 0) report("Deobfuscating", (i / safeTotal) * 30);
            }

            report("Decrypting", 30);
            const tag = s1.subarray(totalBytes - 16);
            const ciphertext = s1.subarray(0, totalBytes - 16);
            
            const nTag = cmac(key, 0, iv);
            const hTag = cmac(key, 1, Buffer.alloc(0));
            const cTag = cmac(key, 2, ciphertext);
            if (!xor(xor(nTag, hTag), cTag).equals(tag)) throw new Error("File Integrity Failed");
            report("Decrypting", 45);
            let decrypted = decryptCTR(key, nTag, ciphertext);

            report("Finalizing", 60);
            const s3 = Buffer.allocUnsafe(decrypted.length);
            const dLen = decrypted.length;
            for (let i = 0; i < dLen; i++) s3[i] = (decrypted[i] ^ (dLen - i)) & 0xFF;

            report("Decompressing", 65);
            
            const limitMb = maxXmlMb || 20; 
            const MAX_XML_OUTPUT = 1024 * 1024 * limitMb; 
            const zlibOptions = { maxOutputLength: MAX_XML_OUTPUT };

            try { 
                finalXML = zlib.inflateSync(s3.subarray(4), zlibOptions).toString(); 
            } 
            catch (e) { 
                try {
                    finalXML = zlib.inflateRawSync(s3.subarray(4), zlibOptions).toString();
                } catch (zlibErr) {
                    throw new Error("Decompression failed or file too large.");
                }
            }
        }

        report("Grading...", 70);
        const fullConfig = toml.parse(configData);
        
        const labConfig = (fullConfig.labs || []).find(l => l.id === labId);
        if (!labConfig) throw new Error("Lab configuration not found.");

        finalXML = stripDoctypeCompletely(finalXML);
        finalXML = finalXML.replace(/<!ENTITY[^>]*>/gi, "");
        finalXML = finalXML.replace(/<\?(?!xml\s)[^?]*\?>/gi, "");

        const parser = new xml2js.Parser({
            strict: true,
            xmlns: false,
            entityExpansionMaxDepth: 1
        });
        const xmlObj = await parser.parseStringPromise(finalXML);
        const devMap = {};
        const devList = xmlObj?.PACKETTRACER5_ACTIVITY?.PACKETTRACER5?.[0]?.NETWORK?.[0]?.DEVICES?.[0]?.DEVICE || [];
        
        devList.forEach(d => {
            const nameObj = d.ENGINE[0].NAME[0];
            const name = String(nameObj._ || nameObj).trim();
            devMap[name] = {
                xmlRoot: d.ENGINE[0],
                running: parseCiscoConfig(d.ENGINE?.[0]?.RUNNINGCONFIG?.[0]?.LINE || []),
                startup: parseCiscoConfig(d.ENGINE?.[0]?.STARTUPCONFIG?.[0]?.LINE || [])
            };
        });
		
        let currentScore = 0;
        let maxScore = 0;
        const serverResults = [];
        const clientResults = [];

        const checks = labConfig.checks || [];
        const showMsgs = (labConfig.show_check_messages !== false);
        const showMissed = (labConfig.show_missed_points === true);

        checks.forEach(check => {
            const pts = parseInt(check.points);
            if (pts > 0) maxScore += pts;
            
            const device = devMap[check.device];
            let pass = false;

            let checkContext = 'global';
            if (check.pass && check.pass.length > 0) {
                checkContext = check.pass[0].context || (check.pass[0].type.startsWith('Xml') ? 'hardware' : 'global');
            } else if (check.passoverride && check.passoverride.length > 0) {
                checkContext = check.passoverride[0].context || 'global';
            }

            if (device) {
                const failCond = check.fail && check.fail.some(c => evaluateCondition(device, c));
                if (!failCond) {
                    if (check.passoverride && check.passoverride.some(c => evaluateCondition(device, c))) {
                        pass = true;
                    } 
                    else if (check.pass && check.pass.length > 0) {
                        pass = check.pass.every(c => evaluateCondition(device, c));
                    }
                }
            }

            if (pass) {
                currentScore += pts;
                if (showMsgs) {
                    clientResults.push({ message: check.message, points: pts, passed: true, device: check.device, context: checkContext });
                }
            } else {
                if (showMsgs && showMissed) {
                    clientResults.push({ message: check.message, points: 0, passed: false, device: check.device, context: checkContext });
                }
            }

            serverResults.push({
                message: check.message,
                device: check.device,
                context: checkContext,
                possible: pts,
                awarded: pass ? pts : 0,
                passed: pass
            });
        });

        if (currentScore < 0) currentScore = 0;
        report("Complete", 100);

        const showScore = (labConfig.show_score !== false);

        parentPort.postMessage({
            type: 'result',
            xml: finalXML,
            grading: {
                total: currentScore,
                max: maxScore,
                clientBreakdown: showMsgs ? clientResults : null,
                serverBreakdown: serverResults,
                show_score: showScore
            }
        });

    } catch (err) {
        const safeMessage = sanitizeErrorMessage(err.message);
        parentPort.postMessage({ type: 'error', msg: safeMessage });
    }
})();

function stripDoctypeCompletely(xml) {
    let result = xml;
    let safety = 0;
    
    while (safety < 10) {
        const dtStart = result.search(/<!DOCTYPE/i);
        if (dtStart === -1) break;
        
        let depth = 0;
        let i = dtStart;
        let found = false;
        
        for (; i < result.length; i++) {
            if (result[i] === '[') depth++;
            else if (result[i] === ']') depth--;
            else if (result[i] === '>' && depth <= 0) {
                found = true;
                break;
            }
        }
        
        if (found) {
            result = result.substring(0, dtStart) + result.substring(i + 1);
        } else {
            result = result.substring(0, dtStart);
            break;
        }
        safety++;
    }
    
    return result;
}

function sanitizeErrorMessage(rawMessage) {
    if (!rawMessage) return "An unknown error occurred during grading.";
    
    const msg = rawMessage.toLowerCase();
    
    if (msg.includes('file integrity failed')) return "File integrity check failed. The file may be corrupted.";
    if (msg.includes('decompression failed') || msg.includes('too large')) return "File decompression failed or exceeds size limits.";
    if (msg.includes('lab configuration not found')) return "Lab configuration not found for the selected lab.";
    if (msg.includes('unexpected end')) return "The uploaded file appears to be incomplete or corrupted.";
    if (msg.includes('invalid xml') || msg.includes('not well-formed') || msg.includes('xml')) return "The file contains invalid or malformed data.";
    if (msg.includes('toml') || msg.includes('parse')) return "Server configuration error. Contact your instructor.";
    
    return "An error occurred while processing your submission.";
}