// os_detector.js
// Infers OS and Server software from headers.

/**
 * Analyzes headers to guess OS/Server.
 * @param {Object} headers - Key-value pair of headers
 * @returns {Object} - { os: string, server: string, accuracy: number }
 */
function detectOS(headers) {
    let os = 'Unknown';
    let server = 'Unknown';
    let accuracy = 0;

    // Normalize headers keys
    const nHeaders = {};
    for (const k in headers) nHeaders[k.toLowerCase()] = headers[k];

    // Server Header Analysis
    if (nHeaders['server']) {
        server = nHeaders['server'];
        const s = server.toLowerCase();

        if (s.includes('ubuntu')) { os = 'Linux (Ubuntu)'; accuracy = 90; }
        else if (s.includes('debian')) { os = 'Linux (Debian)'; accuracy = 90; }
        else if (s.includes('centos')) { os = 'Linux (CentOS)'; accuracy = 90; }
        else if (s.includes('fedora')) { os = 'Linux (Fedora)'; accuracy = 90; }
        else if (s.includes('win32') || s.includes('microsoft-iis')) { os = 'Windows Server'; accuracy = 95; }
        else if (s.includes('apache')) {
            os = 'Linux/Unix (Apache)';
            accuracy = Math.max(accuracy, 60);
        }
        else if (s.includes('nginx')) {
            os = 'Linux/BSD (Nginx)';
            accuracy = Math.max(accuracy, 60);
        }
        else if (s.includes('cloudflare')) { os = 'Cloudflare Edge (Linux)'; accuracy = 80; }
        else if (s.includes('litespeed')) { os = 'Linux (LiteSpeed)'; accuracy = 85; }
    }

    // X-Powered-By & CMS Detection
    let cms = 'Unknown';
    if (nHeaders['x-powered-by']) {
        const powered = nHeaders['x-powered-by'];
        if (powered.includes('ASP.NET')) { os = 'Windows'; accuracy = 95; }
        if (powered.includes('PHP')) {
            if (os === 'Unknown') os = 'Linux/Unix';
            accuracy = Math.max(accuracy, 50);
        }
        if (powered.includes('Express')) { os = 'Linux/Node.js'; accuracy = 70; }
    }

    // Security & Infrastructure Headers
    if (nHeaders['x-vcl-host']) { os = 'Fastly Edge'; accuracy = 90; }
    if (nHeaders['x-vercel-id']) { os = 'Vercel (Serverless)'; accuracy = 95; }
    if (nHeaders['x-amz-cf-id']) { os = 'AWS CloudFront'; accuracy = 80; }

    // Common CMS Headers
    if (nHeaders['x-generator'] || nHeaders['wp-generator']) {
        cms = nHeaders['x-generator'] || nHeaders['wp-generator'];
        if (cms.toLowerCase().includes('wordpress')) {
            cms = 'WordPress';
            if (os === 'Unknown') os = 'Linux (likely)';
        }
    } else if (server.includes('WordPress')) {
        cms = 'WordPress';
    }

    return { os, server, cms, accuracy };
}

self.OSDetector = { detectOS };
