// network_tools.js
// Uses HackerTarget.com API for accurate network reconnaissance tools.
// Free tier: 100 API queries/day. Returns plain text results.

const HT_BASE = 'https://api.hackertarget.com';

/**
 * Generic HackerTarget API call.
 * @param {string} endpoint - API endpoint (e.g., 'mtr', 'nmap', 'dnslookup')
 * @param {string} target - Domain or IP to query
 * @returns {Promise<string>} - Raw text result from API
 */
async function htQuery(endpoint, target) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout

    try {
        const url = `${HT_BASE}/${endpoint}/?q=${encodeURIComponent(target)}`;
        const res = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (text.startsWith('error')) {
            throw new Error(text);
        }
        return text;
    } catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            console.error(`[NetworkTools] ${endpoint} timed out for ${target}`);
            return `Error: Request timed out after 60 seconds. Try again later.`;
        }
        console.error(`[NetworkTools] ${endpoint} failed for ${target}:`, e);
        return `Error: ${e.message}`;
    }
}

/**
 * Traceroute (MTR) - Shows network path to target
 */
async function traceroute(target) {
    return await htQuery('mtr', target);
}

/**
 * Ping (Nping) - Tests host availability
 */
async function ping(target) {
    return await htQuery('nping', target);
}

/**
 * Nmap Port Scan - Scans common ports on target
 */
async function nmapScan(target) {
    return await htQuery('nmap', target);
}

/**
 * DNS Lookup - Retrieves DNS records
 */
async function dnsLookup(target) {
    return await htQuery('dnslookup', target);
}

/**
 * Reverse DNS - Finds hostname for an IP
 */
async function reverseDns(target) {
    return await htQuery('reversedns', target);
}

/**
 * Reverse IP Lookup - Finds all domains hosted on an IP
 */
async function reverseIp(target) {
    return await htQuery('reverseiplookup', target);
}

/**
 * Whois Lookup - Domain/IP registration info
 */
async function whoisLookup(target) {
    return await htQuery('whois', target);
}

/**
 * GeoIP Lookup - Geographic location of IP
 */
async function geoipLookup(target) {
    return await htQuery('geoip', target);
}

/**
 * ASN Lookup - Autonomous System Number info
 */
async function asnLookup(target) {
    return await htQuery('aslookup', target);
}

/**
 * HTTP Headers - Retrieves HTTP response headers
 */
async function httpHeaders(target) {
    return await htQuery('httpheaders', target);
}

/**
 * Page Links - Extracts all links from a page
 */
async function pageLinks(target) {
    return await htQuery('pagelinks', target);
}

/**
 * Subnet Calculator - Calculates subnet information
 */
async function subnetCalc(target) {
    return await htQuery('subnetcalc', target);
}

// Export for usage in background.js
self.NetworkTools = {
    traceroute,
    ping,
    nmapScan,
    dnsLookup,
    reverseDns,
    reverseIp,
    whoisLookup,
    geoipLookup,
    asnLookup,
    httpHeaders,
    pageLinks,
    subnetCalc
};
