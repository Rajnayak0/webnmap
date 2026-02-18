// dir_bruter.js
// Performs directory/file brute forcing using user-provided wordlists.

/**
 * Brute forces directories on a target.
 * @param {string} baseUrl - The base URL (e.g., http://1.2.3.4:8080)
 * @param {string[]} wordlist - Array of paths to check
 * @param {Function} onProgress - Callback for progress updates
 * @returns {Promise<Object[]>} - Array of found paths with status codes
 */
async function bruteForce(baseUrl, wordlist, onProgress) {
    const results = [];
    const concurrency = 5; // Low concurrency to avoid browser issues
    const timeout = 3000;

    // Ensure baseUrl doesn't end with slash
    const base = baseUrl.replace(/\/$/, "");

    for (let i = 0; i < wordlist.length; i += concurrency) {
        const chunk = wordlist.slice(i, i + concurrency);
        const promises = chunk.map(async (path) => {
            const fullUrl = `${base}/${path.startsWith('/') ? path.slice(1) : path}`;
            try {
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), timeout);

                const res = await fetch(fullUrl, {
                    method: 'HEAD',
                    mode: 'no-cors', // Limited info but can detect existence
                    signal: controller.signal
                });

                clearTimeout(id);

                // With no-cors, we can't see status codes clearly unless it's an opaque response.
                // However, if it doesn't THROW, it usually means something is there.
                // If it throws "Failed to fetch", it's likely a 404 or connection error.

                results.push({ path: fullUrl, status: 'EXISTING (OPAQUE)', found: true });
                if (onProgress) onProgress({ path: fullUrl, status: 'FOUND' });

            } catch (e) {
                // If it fails, it might still exist but be blocked by CORS or actually 404.
                // Brute forcing in browser is tricky due to CORS.
                // We'll focus on what we CAN detect.
            }
        });

        await Promise.all(promises);
        if (onProgress) onProgress({ current: i + chunk.length, total: wordlist.length });
    }

    return results;
}

self.DirBruter = { bruteForce };
