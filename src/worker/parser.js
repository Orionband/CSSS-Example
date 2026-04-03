function getXmlValue(rootObj, pathArray) {
    let current = rootObj;
    for (let i = 0; i < pathArray.length; i++) {
        let key = pathArray[i];
        if (current === undefined || current === null) return null;

        // If current is an array, try to navigate intelligently
        if (Array.isArray(current)) {
            const isIndex = typeof key === 'number' || (typeof key === 'string' && /^\d+$/.test(key));
            if (isIndex) {
                current = current[parseInt(key)];
            } else {
                // Auto-unwrap single-element arrays before accessing property
                if (current.length === 1 && current[0] && typeof current[0] === 'object' && current[0][key] !== undefined) {
                    current = current[0][key];
                } else {
                    // Try the key directly on the array (won't usually work, but fallback)
                    current = current[key];
                }
            }
        } else if (typeof current === 'object') {
            current = current[key];
        } else {
            // current is a primitive but we still have path segments left
            return null;
        }
    }

    // Final value extraction — unwrap xml2js structures
    return unwrapValue(current);
}

/**
 * Unwrap xml2js value representations:
 * - { _: "text", $: { attr: "val" } } => "text"
 * - ["single"] => "single"
 * - [{ _: "text" }] => "text"
 * - primitive => primitive
 */
function unwrapValue(val) {
    if (val === undefined || val === null) return val;

    // Unwrap single-element arrays recursively
    if (Array.isArray(val)) {
        if (val.length === 1) {
            return unwrapValue(val[0]);
        }
        return val;
    }

    // Unwrap xml2js text node objects
    if (typeof val === 'object' && '_' in val) {
        return val._;
    }

    return val;
}

function parseCiscoConfig(lines) {
    if (!lines || lines.length === 0) return { global: [], blocks: {} };
    const config = { global: [], blocks: {} };
    let currentBlock = null;
    lines.forEach(rawLine => {
        const line = typeof rawLine === 'string' ? rawLine : rawLine._;
        if (!line) return;
        const trimmed = line.trim();
        if (trimmed === '!' || trimmed === '' || trimmed === 'end') return;
        if (line.startsWith(' ')) {
            if (currentBlock) config.blocks[currentBlock].push(trimmed);
        } else {
            currentBlock = trimmed;
            if (!config.blocks[currentBlock]) config.blocks[currentBlock] = [];
            config.global.push(trimmed);
        }
    });
    return config;
}

module.exports = { getXmlValue, parseCiscoConfig };