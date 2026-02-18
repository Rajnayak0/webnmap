// vuln_scanner.js
// Checks for common exposed files and version-based CVEs.

const RISKY_PATHS = [
    '/.env',
    '/.git/HEAD',
    '/wp-config.php.bak',
    '/config.php.bak',
    '/.vscode/sftp.json',
    '/server-status'
];

async function checkExposedFiles(domain) {
    const protocol = 'https://'; // Default to HTTPS
    const results = [];

    for (const path of RISKY_PATHS) {
        try {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), 1000);

            const res = await fetch(`${protocol}${domain}${path}`, {
                method: 'HEAD',
                signal: controller.signal
            });

            if (res.status === 200) {
                results.push({
                    type: 'Exposed File',
                    severity: 'HIGH',
                    detail: `Found reachable file: ${path}`
                });
            }
        } catch (e) {
            // Ignore fetch errors (likely blocked or 404 handled oddly)
        }
    }
    return results;
}

function checkVersionVulns(serverHeader) {
    const vulns = [];
    if (!serverHeader) return vulns;

    // Example checks (Logic would need a real DB for production)
    if (serverHeader.includes('Apache/2.4.49')) {
        vulns.push({
            type: 'CVE-2021-41773',
            severity: 'CRITICAL',
            detail: 'Apache Path Traversal'
        });
    }

    if (serverHeader.includes('PHP/5.')) {
        vulns.push({
            type: 'EOL Software',
            severity: 'MEDIUM',
            detail: 'PHP 5.x is End of Life'
        });
    }

    return vulns;
}

self.VulnScanner = { checkExposedFiles, checkVersionVulns };
