// site_mapper.js
// Analyzes robots.txt and sitemaps.

async function analyzeStructure(domain) {
    const protocol = 'https://';
    const result = {
        robots: null,
        sitemaps: [],
        disallowed: []
    };

    // Check robots.txt
    try {
        const res = await fetch(`${protocol}${domain}/robots.txt`);
        if (res.ok) {
            const text = await res.text();
            result.robots = "Found";

            // Parse Disallow
            const lines = text.split('\n');
            lines.forEach(line => {
                if (line.trim().toLowerCase().startsWith('disallow:')) {
                    result.disallowed.push(line.split(':')[1].trim());
                }
                if (line.trim().toLowerCase().startsWith('sitemap:')) {
                    result.sitemaps.push(line.split(':')[1].trim());
                }
            });
        } else {
            result.robots = "Not Found";
        }
    } catch (e) {
        result.robots = "Error";
    }

    // Check common sitemap if not found in robots
    if (result.sitemaps.length === 0) {
        try {
            const res = await fetch(`${protocol}${domain}/sitemap.xml`, { method: 'HEAD' });
            if (res.ok) result.sitemaps.push(`${protocol}${domain}/sitemap.xml`);
        } catch (e) { }
    }

    return result;
}

self.SiteMapper = { analyzeStructure };
