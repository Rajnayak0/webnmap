// popup.js

document.addEventListener('DOMContentLoaded', async () => {
    const currentDomainEl = document.getElementById('current-domain');
    const riskScoreEl = document.getElementById('risk-score');

    // Get Current Tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url && tab.url.startsWith('http')) {
        const domain = new URL(tab.url).hostname;
        currentDomainEl.textContent = domain;

        // Manual Scan Button Logic - Open Dashboard
        const btn = document.getElementById('manual-scan-btn');
        btn.textContent = "OPEN DASHBOARD & SCAN";
        btn.addEventListener('click', () => {
            chrome.tabs.create({ url: `dashboard/dashboard.html?target=${domain}` });
        });

        // Request Passive Info
        chrome.runtime.sendMessage({ action: "get_domain_info", domain: domain }, (response) => {
            if (response && response.risk) {
                riskScoreEl.textContent = response.risk;
                if (response.risk === 'HIGH') riskScoreEl.classList.add('risk-high');
            }
        });
    }
});
