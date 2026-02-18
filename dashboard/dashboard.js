// dashboard.js

document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    const navBtns = document.querySelectorAll('.nav-btn');
    const sections = document.querySelectorAll('.view-section');

    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            navBtns.forEach(b => b.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // Target Init
    const urlParams = new URLSearchParams(window.location.search);
    let target = urlParams.get('target') || '';
    const targetInput = document.getElementById('target-input');

    if (target) {
        document.getElementById('target-host').textContent = target;
        targetInput.value = target;
    }

    function getTarget() {
        return targetInput.value.trim() || target;
    }

    // Full Scan Button
    document.getElementById('start-scan-btn').addEventListener('click', () => {
        const t = getTarget();
        if (t) {
            target = t;
            document.getElementById('target-host').textContent = t;
            initiateScan(t);
        }
    });

    // === Individual Tool Run Buttons ===
    document.querySelectorAll('.tool-run-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tool = btn.getAttribute('data-tool');
            const t = getTarget();
            if (!t) {
                alert('Please enter a target domain or IP');
                return;
            }
            target = t;
            document.getElementById('target-host').textContent = t;
            runTool(tool, t, btn);
        });
    });

    // Listen for updates from background
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.action === "scan_complete" && (msg.domain === target || msg.result?.full_target === target)) {
            updateDashboard(msg.result);
        }
        if (msg.action === "scan_progress") {
            handleScanProgress(msg);
        }
    });

    // My Details Button
    document.getElementById('connect-btn').addEventListener('click', () => {
        window.open('https://www.linkedin.com/in/madanraj0', '_blank');
    });

    // Wordlist handling
    document.getElementById('load-common-btn').addEventListener('click', () => {
        const common = ['admin', 'config', '.env', 'api', 'v1', 'backup', 'login', 'dashboard', 'setup', 'test', 'dev', 'wp-admin', 'robots.txt', 'sitemap.xml'];
        document.getElementById('wordlist-input').value = common.join('\n');
    });

    document.getElementById('wordlist-file').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                document.getElementById('wordlist-input').value = event.target.result;
            };
            reader.readAsText(file);
        }
    });

    // Export XML Button
    document.getElementById('export-btn').addEventListener('click', () => {
        exportResultsAsXml();
    });

    // Allow pressing Enter in target input
    targetInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('start-scan-btn').click();
        }
    });
});

// ============================
// Tool Runner (Individual Tools)
// ============================
function runTool(tool, target, btn) {
    const toolMap = {
        'nmap': { action: 'ht_nmap', resultEl: 'nmap-results', label: 'Nmap Scan' },
        'dns': { action: 'ht_dns', resultEl: 'dns-results', label: 'DNS Lookup' },
        'reverse_dns': { action: 'ht_reverse_dns', resultEl: 'reverse-dns-results', label: 'Reverse DNS' },
        'reverse_ip': { action: 'ht_reverse_ip', resultEl: 'reverse-ip-results', label: 'Reverse IP' },
        'traceroute': { action: 'ht_traceroute', resultEl: 'trace-results', label: 'Traceroute' },
        'ping': { action: 'ht_ping', resultEl: 'ping-results', label: 'Ping' },
        'whois': { action: 'ht_whois', resultEl: 'whois-results', label: 'Whois' },
        'geoip': { action: 'ht_geoip', resultEl: 'geoip-results', label: 'GeoIP' },
        'asn': { action: 'ht_asn', resultEl: 'asn-results', label: 'ASN Lookup' },
        'http_headers': { action: 'ht_http_headers', resultEl: 'headers-results', label: 'HTTP Headers' },
        'page_links': { action: 'ht_page_links', resultEl: 'links-results', label: 'Page Links' }
    };

    const config = toolMap[tool];
    if (!config) return;

    const resultEl = document.getElementById(config.resultEl);
    const originalText = btn.textContent;

    // Show loading state
    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    btn.classList.add('scanning-btn');

    const baseMsg = `[*] Running ${config.label} on ${target}...\n[*] Sending request to API...\n[*] Please wait (Nmap scans can take 10-30 seconds)...\n\n`;
    resultEl.textContent = baseMsg;

    // Clean spinner animation
    const spinChars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let spinIdx = 0;
    let elapsed = 0;
    const loadingInterval = setInterval(() => {
        elapsed++;
        resultEl.textContent = baseMsg + `${spinChars[spinIdx % spinChars.length]}  Scanning... (${elapsed}s)`;
        spinIdx++;
    }, 1000);

    // Timeout after 90 seconds
    const timeoutId = setTimeout(() => {
        clearInterval(loadingInterval);
        btn.disabled = false;
        btn.textContent = originalText;
        btn.classList.remove('scanning-btn');
        resultEl.textContent = `[!] Timeout: Scan took longer than 90 seconds.\n[!] The API server may be busy. Try again later.`;
    }, 90000);

    chrome.runtime.sendMessage({ action: config.action, target: target }, (response) => {
        clearInterval(loadingInterval);
        clearTimeout(timeoutId);
        btn.disabled = false;
        btn.textContent = originalText;
        btn.classList.remove('scanning-btn');

        if (response && response.data) {
            const timestamp = new Date().toISOString();
            resultEl.textContent = `[+] ${config.label} Results for: ${target}\n[+] Timestamp: ${timestamp}\n${'='.repeat(60)}\n\n${response.data}`;
        } else {
            resultEl.textContent = `[!] Error: No response received. The API may be rate-limited (100 free queries/day).\n[!] Try again later or check your network connection.`;
        }
    });
}

// ============================
// Full Active Scan
// ============================
function initiateScan(target) {
    const statusEl = document.getElementById('scan-status');
    const logEl = document.getElementById('metadata-content');
    const wordlistInput = document.getElementById('wordlist-input').value;
    const wordlist = wordlistInput.split('\n').map(l => l.trim()).filter(l => l !== '');

    statusEl.textContent = "RUNNING";
    statusEl.style.color = '#ffaa00';
    logEl.textContent = `[+] Starting webnmap full scan on ${target}...\n[+] Timestamp: ${new Date().toISOString()}`;
    if (wordlist.length > 0) logEl.textContent += `\n[+] Directory brute force enabled (${wordlist.length} paths).`;
    logEl.textContent += `\n[*] Running Nmap, DNS, Whois, GeoIP, Traceroute, HTTP Headers...`;
    logEl.textContent += `\n[*] This may take 30-60 seconds...`;

    // Reset progress
    document.getElementById('dir-progress-bar').style.width = '0%';
    document.getElementById('dir-results').textContent = "[+] Scan started...";

    // Send start message
    chrome.runtime.sendMessage({
        action: "start_active_scan",
        domain: target,
        wordlist: wordlist
    });
}

function updateDashboard(data) {
    document.getElementById('scan-status').textContent = "COMPLETE";
    document.getElementById('scan-status').style.color = '#00ff00';
    const logEl = document.getElementById('metadata-content');
    logEl.textContent += `\n[+] Scan finished at ${new Date().toISOString()}`;

    const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(data.domain);
    const targetIp = isIP ? data.domain : (data.rec_a?.[0]?.data || "Unknown");
    const reverseHost = data.rec_ptr?.[0]?.data || "";

    document.getElementById('target-ip').textContent = targetIp;

    // Overview Stats
    const openPorts = data.ports ? data.ports.filter(p => p.state === 'OPEN') : [];
    document.getElementById('stat-ports').textContent = openPorts.length;
    document.getElementById('stat-subs').textContent = data.subdomains?.length || 0;
    document.getElementById('stat-vulns').textContent = data.vulns?.length || 0;
    document.getElementById('stat-os').textContent = `${data.os?.os || "Unknown"} ${data.os?.cms && data.os?.cms !== 'Unknown' ? '(' + data.os.cms + ')' : ''}`;

    // === Nmap Results (from API) ===
    if (data.nmap_raw) {
        const nmapEl = document.getElementById('nmap-results');
        const timestamp = new Date().toISOString();
        nmapEl.textContent = `[+] Nmap Scan Results for: ${data.domain}\n[+] Timestamp: ${timestamp}\n${'='.repeat(60)}\n\n${data.nmap_raw}`;
    }

    // === Port Scan Table (browser-based) ===
    try {
        const portResultsEl = document.getElementById('port-results');
        let portTable = "PORT     STATE    SERVICE    VERSION\n------------------------------------\n";

        if (data.ports && Array.isArray(data.ports)) {
            let foundAny = false;
            data.ports.forEach(p => {
                const state = p.state || 'UNKNOWN';
                if (state !== 'CLOSED') {
                    foundAny = true;
                    const pNum = (p.port || '?').toString().padEnd(8);
                    const pState = state.padEnd(8);
                    const pService = (p.service || 'unknown').padEnd(10);
                    portTable += `${pNum} ${pState} ${pService} unknown\n`;
                }
            });
            if (!foundAny) portTable += "(No open ports detected in browser scan)";
        } else {
            portTable += "(No port data available)";
        }
        portResultsEl.textContent = portTable;
    } catch (e) {
        console.error("Port table rendering failed", e);
        document.getElementById('port-results').textContent = "Error rendering port results: " + e.message;
    }

    // === Traceroute ===
    if (data.traceroute_raw) {
        document.getElementById('trace-results').textContent =
            `[+] Traceroute Results for: ${data.domain}\n${'='.repeat(60)}\n\n${data.traceroute_raw}`;
    }

    // === Whois ===
    if (data.whois_raw) {
        document.getElementById('whois-results').textContent =
            `[+] Whois Results for: ${data.domain}\n${'='.repeat(60)}\n\n${data.whois_raw}`;
    }

    // === GeoIP ===
    if (data.geoip_raw) {
        document.getElementById('geoip-results').textContent =
            `[+] GeoIP Results for: ${data.domain}\n${'='.repeat(60)}\n\n${data.geoip_raw}`;
    }

    // === HTTP Headers ===
    if (data.http_headers_raw) {
        document.getElementById('headers-results').textContent =
            `[+] HTTP Headers for: ${data.domain}\n${'='.repeat(60)}\n\n${data.http_headers_raw}`;
    }

    // Vulns
    const vulnResultsEl = document.getElementById('vuln-results');
    if (data.vulns && data.vulns.length > 0) {
        let vulnText = "";
        data.vulns.forEach(v => {
            vulnText += `[${v.severity}] ${v.type}: ${v.detail}\n`;
        });
        vulnResultsEl.textContent = vulnText;
    } else {
        vulnResultsEl.textContent = "No vulnerabilities detected.";
    }

    // Structure
    const structureEl = document.getElementById('structure-content');
    if (data.structure) {
        let s = data.structure;
        let sText = `Robots.txt: ${s.robots || 'Unknown'}\n\nSitemaps:\n${(s.sitemaps && s.sitemaps.join('\n')) || 'None'}\n\nDisallow Entries:\n${(s.disallowed && s.disallowed.join('\n')) || 'None'}`;
        structureEl.textContent = sText;
    }

    // Directory Brute Results
    try {
        const dirResultsEl = document.getElementById('dir-results');
        if (dirResultsEl) {
            if (data.dir_brute && data.dir_brute.length > 0) {
                let dirText = "[+] Found Paths:\n";
                data.dir_brute.forEach(d => {
                    const status = (d.status || 'UNKNOWN').toString().padEnd(20);
                    const path = d.path || 'unknown';
                    dirText += `${status} ${path}\n`;
                });
                dirResultsEl.textContent = dirText;
                document.getElementById('dir-progress-bar').style.width = '100%';
            } else {
                dirResultsEl.textContent = "No additional directories found or wordlist empty.";
            }
        }
    } catch (e) {
        console.error("Dir brute rendering failed", e);
    }

    // DNS Graph
    try {
        renderGraph(data);
    } catch (e) {
        console.error("Graph rendering failed", e);
        const graphContainer = document.getElementById('network-graph');
        if (graphContainer) {
            graphContainer.innerHTML = `<div style="padding:20px; color:orange;">Graph visualization error: ${e.message}<br>Check if vis-network.min.js is loaded.</div>`;
        }
    }
}

function handleScanProgress(msg) {
    if (msg.type === 'dir_brute') {
        const progress = msg.data;
        if (progress.current !== undefined) {
            const percent = (progress.current / progress.total) * 100;
            document.getElementById('dir-progress-bar').style.width = `${percent}%`;
        }
        if (progress.status === 'FOUND') {
            const resultsEl = document.getElementById('dir-results');
            if (resultsEl.textContent === "[+] Scan started...") resultsEl.textContent = "";
            resultsEl.textContent += `[FOUND] ${progress.path}\n`;
        }
    }
}

function renderGraph(data) {
    if (typeof vis === 'undefined') {
        throw new Error("vis.js library not loaded");
    }
    const nodes = new vis.DataSet([]);
    const edges = new vis.DataSet([]);
    let idCounter = 1;

    // Root (Domain)
    const rootId = idCounter++;
    nodes.add({
        id: rootId,
        label: data.domain,
        level: 0,
        color: '#00ff00',
        shape: 'box',
        font: { color: 'white', size: 20 }
    });

    // NS Records Group
    const nsGroupId = idCounter++;
    nodes.add({ id: nsGroupId, label: 'Name Servers', level: 1, color: '#0088ff', shape: 'ellipse' });
    edges.add({ from: rootId, to: nsGroupId });

    // MX Records Group
    const mxGroupId = idCounter++;
    nodes.add({ id: mxGroupId, label: 'Mail Servers', level: 1, color: '#ffaa00', shape: 'ellipse' });
    edges.add({ from: rootId, to: mxGroupId });

    // A Records / IP Group
    const aGroupId = idCounter++;
    nodes.add({ id: aGroupId, label: 'Host IPs (A)', level: 1, color: '#ff3333', shape: 'ellipse' });
    edges.add({ from: rootId, to: aGroupId });

    // Add NS Items
    if (data.rec_ns) {
        data.rec_ns.forEach(ns => {
            const id = idCounter++;
            nodes.add({ id: id, label: ns.data, level: 2, color: '#0088ff', shape: 'dot' });
            edges.add({ from: nsGroupId, to: id });
        });
    }

    // Add MX Items
    if (data.rec_mx) {
        data.rec_mx.forEach(mx => {
            const id = idCounter++;
            nodes.add({ id: id, label: mx.data.split(' ')[1] || mx.data, level: 2, color: '#ffaa00', shape: 'dot' });
            edges.add({ from: mxGroupId, to: id });
        });
    }

    // Add A Items
    if (data.rec_a) {
        data.rec_a.forEach(a => {
            const id = idCounter++;
            nodes.add({ id: id, label: a.data, level: 2, color: '#ff3333', shape: 'dot' });
            edges.add({ from: aGroupId, to: id });
        });
    }

    // Subdomains Group
    if (data.subdomains && data.subdomains.length > 0) {
        const subGroupId = idCounter++;
        nodes.add({ id: subGroupId, label: `Subdomains (${data.subdomains.length})`, level: 1, color: '#00cc00', shape: 'ellipse' });
        edges.add({ from: rootId, to: subGroupId });

        data.subdomains.slice(0, 10).forEach(sub => {
            const id = idCounter++;
            nodes.add({ id: id, label: sub, level: 2, color: '#00cc00', shape: 'dot' });
            edges.add({ from: subGroupId, to: id });
        });
    }

    const container = document.getElementById('network-graph');
    const dataSet = { nodes: nodes, edges: edges };
    const options = {
        nodes: {
            borderWidth: 2,
            shadow: true,
            font: { color: 'white' }
        },
        edges: {
            width: 2,
            shadow: true,
            color: '#555',
            arrows: { to: { enabled: true, scaleFactor: 0.5 } }
        },
        layout: {
            hierarchical: {
                direction: "UD",
                sortMethod: "directed",
                nodeSpacing: 150,
                levelSeparation: 150
            }
        },
        physics: false
    };
    new vis.Network(container, dataSet, options);
}

// ============================
// Export as XML
// ============================
function exportResultsAsXml() {
    const allResults = document.querySelectorAll('.terminal-text');
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<webnmap-report>\n';
    xml += `  <timestamp>${new Date().toISOString()}</timestamp>\n`;
    xml += `  <target>${document.getElementById('target-host').textContent}</target>\n`;

    allResults.forEach(el => {
        const sectionId = el.closest('.view-section')?.id || el.id || 'unknown';
        const content = el.textContent.trim();
        if (content && content !== '[+] Waiting for scan initiation...' && content !== 'Analyzing...') {
            xml += `  <section name="${sectionId}">\n`;
            xml += `    <![CDATA[${content}]]>\n`;
            xml += `  </section>\n`;
        }
    });

    xml += '</webnmap-report>';

    const blob = new Blob([xml], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webnmap_report_${document.getElementById('target-host').textContent}_${Date.now()}.xml`;
    a.click();
    URL.revokeObjectURL(url);
}
