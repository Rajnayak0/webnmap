// network_tools.js
// Multi-API Network Tools with Automatic Failover
// Sends requests to ALL providers simultaneously, returns the FIRST successful result.
// If one API fails or is slow, results come from another provider automatically.

const HT_BASE = 'https://api.hackertarget.com';

// ============================
// Core: Race Multiple APIs
// ============================

/**
 * Sends requests to multiple API providers simultaneously.
 * Returns the first successful result. If all fail, returns the last error.
 * @param {Array<{name: string, fn: Function}>} providers - Array of {name, fn} where fn returns a Promise<string>
 * @returns {Promise<string>} - First successful result with provider label
 */
async function raceApis(providers) {
    if (providers.length === 0) return 'Error: No API providers configured.';
    if (providers.length === 1) {
        try {
            const result = await providers[0].fn();
            return `[Source: ${providers[0].name}]\n\n${result}`;
        } catch (e) {
            return `Error: ${providers[0].name} failed — ${e.message}`;
        }
    }

    // Race all providers — first to succeed wins
    return new Promise((resolve) => {
        let resolved = false;
        let failCount = 0;
        const errors = [];

        providers.forEach(provider => {
            provider.fn()
                .then(result => {
                    if (!resolved && result && !result.startsWith('Error:')) {
                        resolved = true;
                        resolve(`[Source: ${provider.name}]\n\n${result}`);
                    } else if (!resolved) {
                        failCount++;
                        errors.push(`${provider.name}: ${result}`);
                        if (failCount === providers.length) {
                            resolve(`All APIs failed:\n${errors.join('\n')}`);
                        }
                    }
                })
                .catch(err => {
                    if (!resolved) {
                        failCount++;
                        errors.push(`${provider.name}: ${err.message}`);
                        if (failCount === providers.length) {
                            resolve(`All APIs failed:\n${errors.join('\n')}`);
                        }
                    }
                });
        });

        // Global timeout — 60 seconds
        setTimeout(() => {
            if (!resolved) {
                resolved = true;
                resolve('Error: All API requests timed out after 60 seconds.');
            }
        }, 60000);
    });
}

/**
 * Fetch with timeout helper
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = 30000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return res;
    } catch (e) {
        clearTimeout(timeoutId);
        throw e;
    }
}

/**
 * HackerTarget generic query
 */
async function htQuery(endpoint, target) {
    const url = `${HT_BASE}/${endpoint}/?q=${encodeURIComponent(target)}`;
    const res = await fetchWithTimeout(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.startsWith('error') || text.startsWith('API count exceeded')) {
        throw new Error(text);
    }
    return text;
}


// ============================
// DNS Lookup (3 providers)
// ============================
async function dnsLookup(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('dnslookup', target)
        },
        {
            name: 'Google DNS (DoH)',
            fn: async () => {
                const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
                let output = '';
                for (const type of types) {
                    const res = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=${type}`);
                    const json = await res.json();
                    if (json.Answer && json.Answer.length > 0) {
                        json.Answer.forEach(a => {
                            output += `${a.name}\t${type}\t${a.data}\n`;
                        });
                    }
                }
                if (!output) throw new Error('No DNS records found');
                return output;
            }
        },
        {
            name: 'Cloudflare DNS (DoH)',
            fn: async () => {
                const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];
                let output = '';
                for (const type of types) {
                    const res = await fetchWithTimeout(
                        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(target)}&type=${type}`,
                        { headers: { 'Accept': 'application/dns-json' } }
                    );
                    const json = await res.json();
                    if (json.Answer && json.Answer.length > 0) {
                        json.Answer.forEach(a => {
                            output += `${a.name}\t${type}\t${a.data}\n`;
                        });
                    }
                }
                if (!output) throw new Error('No DNS records found');
                return output;
            }
        }
    ]);
}


// ============================
// Reverse DNS (3 providers)
// ============================
async function reverseDns(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('reversedns', target)
        },
        {
            name: 'Google DNS (PTR)',
            fn: async () => {
                const reversed = target.split('.').reverse().join('.');
                const query = `${reversed}.in-addr.arpa`;
                const res = await fetchWithTimeout(`https://dns.google/resolve?name=${query}&type=PTR`);
                const json = await res.json();
                if (json.Answer && json.Answer.length > 0) {
                    return json.Answer.map(a => `${target}\t→\t${a.data}`).join('\n');
                }
                throw new Error('No PTR records found');
            }
        },
        {
            name: 'Cloudflare DNS (PTR)',
            fn: async () => {
                const reversed = target.split('.').reverse().join('.');
                const query = `${reversed}.in-addr.arpa`;
                const res = await fetchWithTimeout(
                    `https://cloudflare-dns.com/dns-query?name=${query}&type=PTR`,
                    { headers: { 'Accept': 'application/dns-json' } }
                );
                const json = await res.json();
                if (json.Answer && json.Answer.length > 0) {
                    return json.Answer.map(a => `${target}\t→\t${a.data}`).join('\n');
                }
                throw new Error('No PTR records found');
            }
        }
    ]);
}


// ============================
// Whois (3 providers)
// ============================
async function whoisLookup(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('whois', target)
        },
        {
            name: 'RDAP (rdap.org)',
            fn: async () => {
                const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
                const endpoint = isIP ? `https://rdap.org/ip/${target}` : `https://rdap.org/domain/${target}`;
                const res = await fetchWithTimeout(endpoint);
                if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
                const json = await res.json();

                let output = '';
                output += `Handle: ${json.handle || 'N/A'}\n`;
                output += `Name: ${json.name || json.ldhName || 'N/A'}\n`;
                if (json.events) {
                    json.events.forEach(e => {
                        output += `${e.eventAction}: ${e.eventDate}\n`;
                    });
                }
                if (json.entities && json.entities.length > 0) {
                    json.entities.forEach(ent => {
                        output += `Entity: ${ent.handle || ''} [${(ent.roles || []).join(', ')}]\n`;
                        if (ent.vcardArray && ent.vcardArray[1]) {
                            ent.vcardArray[1].forEach(v => {
                                if (v[0] === 'fn') output += `  Name: ${v[3]}\n`;
                                if (v[0] === 'adr') output += `  Address: ${Array.isArray(v[3]) ? v[3].filter(Boolean).join(', ') : v[3]}\n`;
                                if (v[0] === 'email') output += `  Email: ${v[3]}\n`;
                                if (v[0] === 'tel') output += `  Phone: ${v[3]}\n`;
                            });
                        }
                    });
                }
                if (json.nameservers) {
                    output += `\nNameservers:\n`;
                    json.nameservers.forEach(ns => {
                        output += `  ${ns.ldhName}\n`;
                    });
                }
                if (!output.trim()) throw new Error('Empty RDAP response');
                return output;
            }
        },
        {
            name: 'ipwhois.io',
            fn: async () => {
                const res = await fetchWithTimeout(`https://ipwhois.app/json/${encodeURIComponent(target)}`);
                const json = await res.json();
                if (!json.success && json.message) throw new Error(json.message);
                let output = '';
                output += `IP: ${json.ip || target}\n`;
                output += `Type: ${json.type || 'N/A'}\n`;
                output += `Country: ${json.country} (${json.country_code})\n`;
                output += `Region: ${json.region}\n`;
                output += `City: ${json.city}\n`;
                output += `ISP: ${json.isp}\n`;
                output += `Org: ${json.org}\n`;
                output += `ASN: ${json.asn}\n`;
                return output;
            }
        }
    ]);
}


// ============================
// GeoIP (4 providers)
// ============================
async function geoipLookup(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('geoip', target)
        },
        {
            name: 'ip-api.com',
            fn: async () => {
                const res = await fetchWithTimeout(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query`);
                const json = await res.json();
                if (json.status === 'fail') throw new Error(json.message);
                let output = '';
                output += `IP: ${json.query}\n`;
                output += `Country: ${json.country} (${json.countryCode})\n`;
                output += `Region: ${json.regionName} (${json.region})\n`;
                output += `City: ${json.city}\n`;
                output += `ZIP: ${json.zip}\n`;
                output += `Latitude: ${json.lat}\n`;
                output += `Longitude: ${json.lon}\n`;
                output += `Timezone: ${json.timezone}\n`;
                output += `ISP: ${json.isp}\n`;
                output += `Org: ${json.org}\n`;
                output += `AS: ${json.as}\n`;
                output += `AS Name: ${json.asname}\n`;
                output += `Reverse DNS: ${json.reverse || 'N/A'}\n`;
                return output;
            }
        },
        {
            name: 'ipapi.co',
            fn: async () => {
                const res = await fetchWithTimeout(`https://ipapi.co/${encodeURIComponent(target)}/json/`);
                const json = await res.json();
                if (json.error) throw new Error(json.reason || json.error);
                let output = '';
                output += `IP: ${json.ip}\n`;
                output += `Country: ${json.country_name} (${json.country_code})\n`;
                output += `Region: ${json.region}\n`;
                output += `City: ${json.city}\n`;
                output += `Postal: ${json.postal}\n`;
                output += `Latitude: ${json.latitude}\n`;
                output += `Longitude: ${json.longitude}\n`;
                output += `Timezone: ${json.timezone}\n`;
                output += `ISP: ${json.org}\n`;
                output += `ASN: ${json.asn}\n`;
                return output;
            }
        },
        {
            name: 'ipwhois.io',
            fn: async () => {
                const res = await fetchWithTimeout(`https://ipwhois.app/json/${encodeURIComponent(target)}`);
                const json = await res.json();
                if (!json.success && json.message) throw new Error(json.message);
                let output = '';
                output += `IP: ${json.ip}\n`;
                output += `Country: ${json.country} (${json.country_code})\n`;
                output += `Region: ${json.region}\n`;
                output += `City: ${json.city}\n`;
                output += `Latitude: ${json.latitude}\n`;
                output += `Longitude: ${json.longitude}\n`;
                output += `Timezone: ${json.timezone}\n`;
                output += `ISP: ${json.isp}\n`;
                output += `Org: ${json.org}\n`;
                output += `ASN: ${json.asn}\n`;
                return output;
            }
        }
    ]);
}


// ============================
// ASN Lookup (3 providers)
// ============================
async function asnLookup(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('aslookup', target)
        },
        {
            name: 'BGPView',
            fn: async () => {
                const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
                const endpoint = isIP
                    ? `https://api.bgpview.io/ip/${target}`
                    : `https://api.bgpview.io/search?query_term=${encodeURIComponent(target)}`;
                const res = await fetchWithTimeout(endpoint);
                const json = await res.json();
                if (json.status !== 'ok') throw new Error('BGPView lookup failed');

                let output = '';
                if (isIP && json.data && json.data.prefixes) {
                    json.data.prefixes.forEach(p => {
                        output += `IP: ${p.ip}\n`;
                        output += `Prefix: ${p.prefix}\n`;
                        output += `ASN: ${p.asn?.asn || 'N/A'}\n`;
                        output += `AS Name: ${p.asn?.name || 'N/A'}\n`;
                        output += `Description: ${p.asn?.description || 'N/A'}\n`;
                        output += `Country: ${p.asn?.country_code || 'N/A'}\n\n`;
                    });
                } else if (json.data) {
                    output = JSON.stringify(json.data, null, 2);
                }
                if (!output.trim()) throw new Error('No ASN data found');
                return output;
            }
        },
        {
            name: 'ip-api.com',
            fn: async () => {
                const res = await fetchWithTimeout(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=status,message,as,asname,isp,org,query`);
                const json = await res.json();
                if (json.status === 'fail') throw new Error(json.message);
                let output = '';
                output += `IP: ${json.query}\n`;
                output += `AS: ${json.as}\n`;
                output += `AS Name: ${json.asname}\n`;
                output += `ISP: ${json.isp}\n`;
                output += `Org: ${json.org}\n`;
                return output;
            }
        }
    ]);
}


// ============================
// HTTP Headers (2 providers)
// ============================
async function httpHeaders(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('httpheaders', target)
        },
        {
            name: 'Direct Fetch',
            fn: async () => {
                const url = target.startsWith('http') ? target : `https://${target}`;
                const res = await fetchWithTimeout(url, { method: 'HEAD', mode: 'no-cors' });
                let output = `HTTP/${res.status} ${res.statusText}\n\n`;
                res.headers.forEach((value, key) => {
                    output += `${key}: ${value}\n`;
                });
                if (output.split('\n').length < 3) throw new Error('No headers captured (CORS blocked)');
                return output;
            }
        }
    ]);
}


// ============================
// Traceroute (2 providers)
// ============================
async function traceroute(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('mtr', target)
        },
        {
            name: 'stat.ripe.net',
            fn: async () => {
                const res = await fetchWithTimeout(`https://stat.ripe.net/data/traceroute/data.json?resource=${encodeURIComponent(target)}`);
                const json = await res.json();
                if (!json.data || !json.data.result) throw new Error('No traceroute data');
                let output = `Traceroute to ${target}:\n`;
                const hops = json.data.result;
                if (Array.isArray(hops)) {
                    hops.forEach((hop, i) => {
                        output += `${i + 1}\t${hop.from || '*'}\t${hop.rtt || '?'} ms\n`;
                    });
                } else {
                    output += JSON.stringify(json.data, null, 2);
                }
                return output;
            }
        }
    ]);
}


// ============================
// Ping (2 providers)
// ============================
async function ping(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('nping', target)
        },
        {
            name: 'Browser Timing',
            fn: async () => {
                const url = target.startsWith('http') ? target : `https://${target}`;
                const results = [];
                for (let i = 0; i < 4; i++) {
                    const start = Date.now();
                    try {
                        await fetchWithTimeout(`${url}?_ping=${Math.random()}`, { mode: 'no-cors' }, 5000);
                        const rtt = Date.now() - start;
                        results.push(rtt);
                    } catch (e) {
                        const rtt = Date.now() - start;
                        if (rtt < 5000) results.push(rtt);
                        else results.push(-1);
                    }
                }
                let output = `Ping ${target}:\n\n`;
                results.forEach((rtt, i) => {
                    if (rtt >= 0) {
                        output += `Reply ${i + 1}: time=${rtt}ms\n`;
                    } else {
                        output += `Reply ${i + 1}: timeout\n`;
                    }
                });
                const valid = results.filter(r => r >= 0);
                if (valid.length > 0) {
                    const avg = Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
                    const min = Math.min(...valid);
                    const max = Math.max(...valid);
                    output += `\nMin: ${min}ms  Max: ${max}ms  Avg: ${avg}ms  Loss: ${Math.round(((results.length - valid.length) / results.length) * 100)}%\n`;
                }
                return output;
            }
        }
    ]);
}


// ============================
// Nmap Scan (HackerTarget only — no other free Nmap API exists)
// ============================
async function nmapScan(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('nmap', target)
        }
    ]);
}


// ============================
// Page Links (2 providers)
// ============================
async function pageLinks(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('pagelinks', target)
        },
        {
            name: 'Direct Extraction',
            fn: async () => {
                const url = target.startsWith('http') ? target : `https://${target}`;
                const res = await fetchWithTimeout(url);
                const html = await res.text();
                const linkRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
                const links = new Set();
                let match;
                while ((match = linkRegex.exec(html)) !== null) {
                    links.add(match[1]);
                }
                if (links.size === 0) throw new Error('No links found');
                return Array.from(links).join('\n');
            }
        }
    ]);
}


// ============================
// Reverse IP (HackerTarget only)
// ============================
async function reverseIp(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('reverseiplookup', target)
        }
    ]);
}


// ============================
// Subnet Calculator (HackerTarget only)
// ============================
async function subnetCalc(target) {
    return raceApis([
        {
            name: 'HackerTarget',
            fn: () => htQuery('subnetcalc', target)
        }
    ]);
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
