// HIBP k-anonymity breach check (Phase J, REQ-045..047).
//
// The full password and its SHA-1 hash NEVER leave the browser. Only the
// first 5 hex characters of the hash are sent to the HIBP API, via a simple
// range query. Response includes ~800 padded entries (Add-Padding: true).
//
// Security model:
//   - SHA-1 is used because HIBP uses SHA-1. This is NOT a cryptographic
//     authentication use — it's a hash-for-lookup. SHA-1's collision
//     weaknesses are irrelevant to this k-anonymity protocol.
//   - The full password never appears in any network request.
//   - The full SHA-1 hash (35 chars beyond the prefix) never leaves the
//     browser — only 5 hex chars of the hash go over the wire.
//   - No data is sent to Dragon Vault's server for this check.

/**
 * Check whether a password has appeared in known data breaches via
 * Have I Been Pwned's k-anonymity API.
 *
 * @param {string} password - The plaintext password to check
 * @param {{signal?: AbortSignal}} [options] - Options object
 * @param {AbortSignal} [options.signal] - Optional AbortSignal to cancel
 *   the fetch (e.g. AbortSignal.timeout(15000)). When the signal fires the
 *   returned promise resolves to {found: false, count: 0, error: true}.
 * @returns {Promise<{found: boolean, count: number, error: boolean}>}
 *   found  — true if the password suffix appears in the HIBP response
 *   count  — number of reported appearances (0 if not found or on error)
 *   error  — true if the network request failed, HTTP status was non-2xx,
 *            or the fetch was aborted (including timeout)
 */
export async function checkHibpBreach(password, { signal } = {}) {
    if (!password) {
        return { found: false, count: 0, error: false };
    }

    try {
        // 1. SHA-1 hash via Web Crypto API (SubtleCrypto).
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashBytes = new Uint8Array(hashBuffer);

        // 2. Convert to uppercase hex string.
        let hashHex = '';
        for (let i = 0; i < hashBytes.length; i++) {
            hashHex += hashBytes[i].toString(16).padStart(2, '0');
        }
        hashHex = hashHex.toUpperCase();

        // 3. Split: 5-char prefix goes to HIBP; the remaining 35 chars stay
        //    in the browser and are compared locally against the response.
        const prefix = hashHex.slice(0, 5);
        const suffix = hashHex.slice(5);

        // 4. k-anonymity range query. Add-Padding: true asks HIBP to return
        //    ~800 entries (padded with fake hashes) so an attacker watching
        //    the response size cannot determine the real match count.
        const response = await fetch(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            { headers: { 'Add-Padding': 'true' }, signal },
        );
        if (!response.ok) {
            return { found: false, count: 0, error: true };
        }

        // 5. Parse the response body. Each non-empty line is:
        //      SUFFIX:COUNT
        //    where SUFFIX is the remaining 35 hex chars of the SHA-1 and
        //    COUNT is the number of times this password appears in breaches.
        const body = await response.text();
        const lines = body.split('\n');
        for (let i = 0; i < lines.length; i++) {
            const trimmed = lines[i].trim();
            if (!trimmed) continue;
            const colonIdx = trimmed.indexOf(':');
            if (colonIdx === -1) continue;
            const lineSuffix = trimmed.slice(0, colonIdx);
            if (lineSuffix === suffix) {
                const countStr = trimmed.slice(colonIdx + 1);
                const count = parseInt(countStr, 10);
                return { found: true, count: isNaN(count) ? 0 : count, error: false };
            }
        }

        // 6. Suffix not found — password is clean (at least per HIBP).
        return { found: false, count: 0, error: false };
    } catch (_err) {
        // Network failure, CORS issue, DNS, timeout, or user-initiated
        // abort via AbortSignal — handle gracefully.
        return { found: false, count: 0, error: true };
    }
}
