// dns_enum.js
// Handles DNS resolution and Subdomain finding.

async function resolveDNS(domain, type = 'A') {
    // Try Google DNS-over-HTTPS
    const url = `https://dns.google/resolve?name=${domain}&type=${type}`;
    try {
        const res = await fetch(url);
        const json = await res.json();
        return json.Answer || [];
    } catch (e) {
        // Fallback to Cloudflare
        try {
            const cfUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`;
            const cfRes = await fetch(cfUrl, { headers: { 'Accept': 'application/dns-json' } });
            const cfJson = await cfRes.json();
            return cfJson.Answer || [];
        } catch (e2) {
            return [];
        }
    }
}

/**
 * Resolves an IP to a hostname (Reverse DNS / PTR record)
 */
async function resolvePTR(ip) {
    if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) return [];

    // Reverse the IP for in-addr.arpa
    const reversed = ip.split('.').reverse().join('.');
    const query = `${reversed}.in-addr.arpa`;

    return await resolveDNS(query, 'PTR');
}

async function findSubdomains(domain) {
    // Uses crt.sh to find subdomains (Certificate Transparency Logs)
    try {
        const res = await fetch(`https://crt.sh/?q=${domain}&output=json`);
        if (!res.ok) throw new Error("CRT.sh failed");

        const json = await res.json();
        const subs = new Set();

        json.forEach(entry => {
            const names = entry.name_value.split('\n');
            names.forEach(n => {
                const cleaned = n.trim().toLowerCase();
                if (cleaned && !cleaned.includes('*') && cleaned.endsWith(domain)) {
                    subs.add(cleaned);
                }
            });
        });

        // Return sorted list
        return Array.from(subs).sort();
    } catch (e) {
        console.error("CRT.sh fetch failed", e);
        // Fallback or just return empty
        return [];
    }
}

self.DNSScanner = { resolveDNS, resolvePTR, findSubdomains };
