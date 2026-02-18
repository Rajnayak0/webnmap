// webnmap - Background Script
importScripts(
  'modules/port_scanner.js',
  'modules/os_detector.js',
  'modules/vuln_scanner.js',
  'modules/dns_enum.js',
  'modules/whois_lookup.js',
  'modules/site_mapper.js',
  'modules/dir_bruter.js',
  'modules/network_tools.js'
);

const SCAN_CACHE = {};

// Initialize or load cache
chrome.storage.local.get(['scanCache'], (result) => {
  if (result.scanCache) {
    Object.assign(SCAN_CACHE, result.scanCache);
  }
});

function saveCache() {
  chrome.storage.local.set({ scanCache: SCAN_CACHE });
}

// Analyze Headers (Passive)
function analyzeHeaders(details) {
  const headers = {};
  if (details.responseHeaders) {
    details.responseHeaders.forEach(h => headers[h.name.toLowerCase()] = h.value);
  }
  return headers;
}

// WebRequest Listener
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === 'main_frame') {
      try {
        const url = new URL(details.url);
        const domain = url.hostname;
        const headers = analyzeHeaders(details);

        if (!SCAN_CACHE[domain]) SCAN_CACHE[domain] = {};

        // Update Passive Info
        SCAN_CACHE[domain].headers = headers;
        SCAN_CACHE[domain].timestamp = Date.now();

        // Run Passive OS Detection
        const osInfo = self.OSDetector.detectOS(headers);
        SCAN_CACHE[domain].os = osInfo;

        // Run Passive Vuln Check (Version)
        const vulns = self.VulnScanner.checkVersionVulns(headers['server']);
        SCAN_CACHE[domain].vulns = (SCAN_CACHE[domain].vulns || []).concat(vulns);

        saveCache();
      } catch (e) {
        console.error("WebRequest analysis failed", e);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Message Handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "get_domain_info") {
    sendResponse(SCAN_CACHE[request.domain] || { risk: 'UNKNOWN', domain: request.domain });
  }

  if (request.action === "start_active_scan") {
    const domain = request.domain;
    const wordlist = request.wordlist || [];
    runActiveScan(domain, wordlist).then(result => {
      chrome.runtime.sendMessage({ action: "scan_complete", domain: result.domain, result: result });
    });
    sendResponse({ status: "started" });
  }

  // === HackerTarget API Tools ===
  if (request.action === "ht_traceroute") {
    self.NetworkTools.traceroute(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_ping") {
    self.NetworkTools.ping(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_nmap") {
    self.NetworkTools.nmapScan(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_dns") {
    self.NetworkTools.dnsLookup(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_reverse_dns") {
    self.NetworkTools.reverseDns(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_reverse_ip") {
    self.NetworkTools.reverseIp(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_whois") {
    self.NetworkTools.whoisLookup(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_geoip") {
    self.NetworkTools.geoipLookup(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_asn") {
    self.NetworkTools.asnLookup(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_http_headers") {
    self.NetworkTools.httpHeaders(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_page_links") {
    self.NetworkTools.pageLinks(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  if (request.action === "ht_subnet") {
    self.NetworkTools.subnetCalc(request.target).then(result => {
      sendResponse({ data: result });
    });
    return true;
  }

  return true; // async
});

async function runActiveScan(domain, wordlist = []) {
  console.log(`[Scan] Starting active scan for: ${domain}`);

  // Robust Target Normalization
  let host = domain;
  let port = null;

  if (domain.includes('://')) {
    try {
      const url = new URL(domain);
      host = url.hostname;
      port = url.port ? parseInt(url.port) : null;
    } catch (e) { }
  } else if (domain.includes(':')) {
    const parts = domain.split(':');
    host = parts[0];
    port = parseInt(parts[1]);
  }

  const result = {
    domain: host,
    full_target: domain,
    target_port: port,
    ports: [],
    subdomains: [],
    vulns: [],
    whois: {},
    structure: {},
    dir_brute: [],
    timestamp: Date.now()
  };

  // 1. Nmap Scan (via API for accuracy)
  console.log(`[Scan] Step 1: Nmap Scanning ${host}...`);
  result.nmap_raw = await self.NetworkTools.nmapScan(host);

  // 2. Also run browser-based port scan for additional detection
  console.log(`[Scan] Step 1b: Browser-based Port Scanning ${host}...`);
  result.ports = await self.PortScanner.scanTarget(host, port);
  const openCount = result.ports.filter(p => p.state === 'OPEN').length;
  console.log(`[Scan] Port Scan finished. ${openCount} ports open.`);

  // 3. DNS/Subdomains
  const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
  if (!isIP) {
    console.log(`[Scan] Step 2: DNS Enumeration for ${host}...`);
    result.rec_a = await self.DNSScanner.resolveDNS(host, 'A');
    result.rec_aaaa = await self.DNSScanner.resolveDNS(host, 'AAAA');
    result.rec_mx = await self.DNSScanner.resolveDNS(host, 'MX');
    result.rec_ns = await self.DNSScanner.resolveDNS(host, 'NS');
    result.rec_txt = await self.DNSScanner.resolveDNS(host, 'TXT');
    result.subdomains = await self.DNSScanner.findSubdomains(host);
    console.log(`[Scan] DNS Enum finished. Found ${result.subdomains.length} subdomains.`);
  } else {
    console.log(`[Scan] Step 2: Target is IP. Reverse DNS (PTR) for ${host}...`);
    result.rec_ptr = await self.DNSScanner.resolvePTR(host);
    console.log(`[Scan] Reverse DNS finished: ${result.rec_ptr?.[0]?.data || "None found"}`);
  }

  // 4. Active Vuln Scan
  console.log(`[Scan] Step 3: Vulnerability Scanning ${host}...`);
  result.vulns = await self.VulnScanner.checkExposedFiles(host);
  console.log(`[Scan] Vuln Scan finished. Found ${result.vulns.length} potential issues.`);

  // 5. Whois (via API for accuracy)
  console.log(`[Scan] Step 4: Whois Lookup for ${host}...`);
  result.whois_raw = await self.NetworkTools.whoisLookup(host);
  if (!isIP) {
    result.whois = await self.WhoisLookup.getWhois(host);
  }
  console.log(`[Scan] Whois finished.`);

  // 6. GeoIP
  console.log(`[Scan] Step 5: GeoIP Lookup for ${host}...`);
  result.geoip_raw = await self.NetworkTools.geoipLookup(host);

  // 7. Traceroute
  console.log(`[Scan] Step 6: Traceroute for ${host}...`);
  result.traceroute_raw = await self.NetworkTools.traceroute(host);

  // 8. HTTP Headers
  console.log(`[Scan] Step 7: HTTP Headers for ${host}...`);
  result.http_headers_raw = await self.NetworkTools.httpHeaders(host);

  // 9. Site Structure & Dir Brute
  const hasWeb = result.ports.some(p => p.state === 'OPEN' && [80, 443, 8080, 8081, 8443, 8888, 9000, 3000].includes(p.port));
  if (hasWeb || !isIP) {
    console.log(`[Scan] Step 8: Site Mapping ${host}...`);
    result.structure = await self.SiteMapper.analyzeStructure(host);
    console.log(`[Scan] Site Mapping finished.`);

    if (wordlist.length > 0) {
      console.log(`[Scan] Step 9: Directory Brute Force starting...`);
      const baseUrl = domain.includes('://') ? domain : `http://${host}`;
      result.dir_brute = await self.DirBruter.bruteForce(baseUrl, wordlist, (progress) => {
        chrome.runtime.sendMessage({ action: "scan_progress", type: 'dir_brute', data: progress });
      });
      console.log(`[Scan] Directory Brute Force finished.`);
    }
  } else {
    console.log(`[Scan] No common web ports open. Skipping web-specific scans.`);
  }

  // Merge into Cache
  if (!SCAN_CACHE[host]) SCAN_CACHE[host] = {};
  Object.assign(SCAN_CACHE[host], result);
  saveCache();

  return result;
}
