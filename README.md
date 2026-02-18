# webnmap — Browser Network Scanner Extension

<p align="center">
  <img src="https://img.shields.io/badge/Manifest-V3-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/API-HackerTarget-green?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Version-1.1.0-brightgreen?style=flat-square" />
</p>

**webnmap** is a Chrome/Edge browser extension for active reconnaissance, port scanning, DNS enumeration, and vulnerability analysis — all from within your browser. It leverages tool sends requests to **all configured API providers simultaneously** and returns the **first successful result** for accurate, real-world network scanning results.

---

## ✨ Features

| Tool | Description |
|---|---|
| **Nmap Scan** | Real port scan with service & version detection |
| **Traceroute (MTR)** | Network path trace with hop-by-hop latency |
| **Ping (Nping)** | Host availability & response time |
| **DNS Lookup** | A, AAAA, MX, NS, TXT record resolution |
| **Reverse DNS** | IP → hostname resolution |
| **Reverse IP** | Find all domains hosted on the same IP |
| **Whois** | Domain/IP registration & ownership info |
| **GeoIP Lookup** | Geographic location of any IP address |
| **ASN Lookup** | Autonomous System Number & ISP info |
| **HTTP Headers** | Full HTTP response headers of any URL |
| **Page Links** | Extract all links from a target page |
| **DNS Map** | Interactive visual graph of DNS records (vis.js) |
| **Vuln Scan** | Check for exposed sensitive files (.env, .git, etc.) |
| **Dir Brute** | Directory brute forcing with custom wordlists |
| **Site Structure** | robots.txt & sitemap.xml analysis |
| **OS Detection** | Server OS & CMS fingerprinting via headers |
| **Port Scan** | Browser-based port connectivity check |

---

## 📸 Screenshots

### Dashboard — Nmap Scan
> The dashboard opens in a new tab with a sidebar containing all 17 tools. Each tool has its own RUN button and terminal-style output area.

### Dashboard — DNS Map
> Interactive graph visualization of DNS records (Name Servers, Mail Servers, A Records, Subdomains).

---

## 🚀 Installation

### From Source (Developer Mode)

1. **Clone this repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/webnmap.git
   ```

2. **Open your browser's extension page**
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`

3. **Enable Developer Mode** (toggle in top-right corner)

4. **Click "Load Unpacked"** and select the `webnmap` folder

5. **Done!** The extension icon will appear in your toolbar.

---

## 🛠️ Usage

1. **Click the extension icon** on any website to see a quick security summary
2. **Click "OPEN DASHBOARD & SCAN"** to open the full scanning dashboard
3. **Enter a target** (domain or IP) in the input field at the top
4. **Click FULL SCAN** to run all tools at once, or click **individual tool RUN buttons** in the sidebar
5. **Export results** as XML using the EXPORT XML button

---

## 📂 Project Structure

```
webnmap/
├── manifest.json              # Extension manifest (MV3)
├── README.md                  # This file
│
├── popup/                     # Browser action popup
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
│
├── dashboard/                 # Full scanning dashboard (new tab)
│   ├── dashboard.html
│   ├── dashboard.css
│   └── dashboard.js
│
├── background/                # Service worker & modules
│   ├── background.js          # Main service worker
│   └── modules/
│       ├── network_tools.js   # Multi-API wrapper with failover (10 providers)
│       ├── port_scanner.js    # Browser-based port scanner
│       ├── dns_enum.js        # DNS resolution & subdomain finding
│       ├── whois_lookup.js    # RDAP-based whois
│       ├── vuln_scanner.js    # Exposed file & CVE checks
│       ├── os_detector.js     # OS/Server fingerprinting
│       ├── site_mapper.js     # robots.txt & sitemap parser
│       └── dir_bruter.js      # Directory brute forcing
│
├── content/                   # Content script
│   └── content.js
│
└── icon/                      # Extension icons
```

---

## 🔌 APIs & Multi-Provider Failover

Each tool sends requests to **all configured API providers simultaneously** and returns the **first successful result**. If one API is down, slow, or rate-limited, results automatically come from another provider.

| Tool | Providers |
|---|---|
| **DNS Lookup** | HackerTarget, Google DoH, Cloudflare DoH |
| **Reverse DNS** | HackerTarget, Google DoH, Cloudflare DoH |
| **Whois** | HackerTarget, RDAP (rdap.org), ipwhois.io |
| **GeoIP** | HackerTarget, ip-api.com, ipapi.co, ipwhois.io |
| **ASN Lookup** | HackerTarget, BGPView, ip-api.com |
| **Traceroute** | HackerTarget, stat.ripe.net |
| **Ping** | HackerTarget, Browser Timing |
| **HTTP Headers** | HackerTarget, Direct Fetch |
| **Page Links** | HackerTarget, Direct Extraction |
| **Nmap Scan** | HackerTarget |
| **Reverse IP** | HackerTarget |

### API Limits (Free Tier)

| Provider | Limit | Key Required |
|---|---|---|
| **HackerTarget** | 100/day | No |
| **Google DNS (DoH)** | Unlimited | No |
| **Cloudflare DNS (DoH)** | Unlimited | No |
| **ip-api.com** | 45/minute | No |
| **ipapi.co** | 1,000/day | No |
| **ipwhois.io** | 10,000/month | No |
| **BGPView** | Unlimited | No |
| **RDAP (rdap.org)** | Unlimited | No |
| **stat.ripe.net** | Unlimited | No |

> ⚠️ Results show `[Source: ProviderName]` so you always know which API returned the data.

---

## 🔒 Permissions

| Permission | Reason |
|---|---|
| `tabs` | Get current tab URL for scanning |
| `storage` | Cache scan results locally |
| `webRequest` | Passively analyze HTTP response headers |
| `activeTab` | Access current tab information |
| `scripting` | Inject content scripts |
| `host_permissions: <all_urls>` | Required for API calls & cross-origin scanning |

---

## 🧑‍💻 Author

**Madan Raj**
- [LinkedIn](https://www.linkedin.com/in/madanraj0)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing purposes only**. Always obtain proper authorization before scanning any network or system you do not own. The author is not responsible for any misuse of this tool.
