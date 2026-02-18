// whois_lookup.js
// Fetches domain registration info via RDAP (Registration Data Access Protocol).

async function getWhois(domain) {
    // Try reliable RDAP endpoints. fallback to a public API if RDAP fails or is complex to parse.
    // rdap.org is a good redirector.
    try {
        const res = await fetch(`https://rdap.org/domain/${domain}`);
        if (!res.ok) throw new Error("RDAP lookup failed");

        const json = await res.json();

        // Parse crucial fields
        const registrar = json.entities ? json.entities[0]?.vcardArray[1][1][3] : "Unknown";
        const events = json.events || [];
        const created = events.find(e => e.eventAction === 'registration')?.eventDate || "Unknown";
        const expires = events.find(e => e.eventAction === 'expiration')?.eventDate || "Unknown";

        return {
            registrar: registrar,
            created: created,
            expires: expires,
            handle: json.handle,
            raw: json
        };
    } catch (e) {
        return { error: "Could not fetch Whois data (CORS or Rate Limit)" };
    }
}

self.WhoisLookup = { getWhois };
