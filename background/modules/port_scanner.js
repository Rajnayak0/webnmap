// port_scanner.js
// Implements a "Connect Scan" using fetch() timing and error handling.

const COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8081, 8082, 8443, 8888, 9000, 9090, 27017
];

const UNSAFE_PORTS = [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 77, 79, 87, 95, 101, 102, 103, 104, 109,
    110, 111, 113, 115, 117, 119, 123, 135, 139, 143, 179, 389, 465, 512, 513, 514, 515, 526, 530, 531, 532,
    540, 556, 563, 587, 601, 636, 993, 995, 2049, 3659, 4045, 6000, 6665, 6666, 6667, 6668, 6669, 6697
];

/**
 * Scans a single port on a host.
 * @param {string} host - Domain or IP
 * @param {number} port - Port number
 * @returns {Promise<string>} - 'OPEN', 'CLOSED', or 'FILTERED'
 */
async function scanPort(host, port) {
    if (UNSAFE_PORTS.includes(port)) {
        return 'BLOCKED';
    }

    const protocols = port === 443 || port === 8443 ? ['https', 'http'] : ['http', 'https'];
    const controller = new AbortController();

    for (const proto of protocols) {
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        const startTime = Date.now();

        try {
            await fetch(`${proto}://${host}:${port}/?nocache=${Math.random()}`, {
                mode: 'no-cors',
                signal: controller.signal,
                credentials: 'omit'
            });
            clearTimeout(timeoutId);
            return 'OPEN';
        } catch (error) {
            clearTimeout(timeoutId);
            const duration = Date.now() - startTime;

            if (error.name === 'AbortError') {
                return 'FILTERED';
            } else if (error.message.includes('Failed to fetch') || error.name === 'TypeError') {
                // If it's a TypeError/Failed to fetch, it might be a protocol error on an OPEN port.
                // If we have another protocol to try, continue.
                if (proto === protocols[0] && protocols[1]) continue;

                if (duration < 500) return 'CLOSED';
                return 'FILTERED';
            }
        }
    }
    return 'CLOSED';
}

async function scanTarget(host, specificPort = null) {
    const results = [];
    const portsToScan = [...COMMON_PORTS];
    if (specificPort && !portsToScan.includes(specificPort)) {
        portsToScan.push(specificPort);
    }

    for (const port of portsToScan) {
        const state = await scanPort(host, port);
        results.push({ port, state, service: getServiceName(port) });
    }
    return results;
}

function getServiceName(port) {
    const services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
        110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
        1723: 'pptp', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
        6379: 'redis', 8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb'
    };
    return services[port] || 'unknown';
}

// Export for usage in background.js
// In extension context, we might attach to global or use modules if configured.
self.PortScanner = { scanTarget };
