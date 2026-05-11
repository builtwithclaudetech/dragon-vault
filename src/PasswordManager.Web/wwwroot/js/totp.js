// Dragon Vault TOTP module (Phase I, REQ-041..044).
//
// RFC 6238 (TOTP) over RFC 4226 (HOTP), 30-second period, 6-digit
// code. Supports SHA-1, SHA-256, and SHA-512 algorithms (OQ-03).
// Default is SHA-1 for backward compatibility.
//
// Public API:
//   - generateTotp(secretBase32, options?) — pure async function. Returns the
//     current 6-digit code as a string. options { period, digits, algorithm, when } are
//     for testability; production callers pass nothing. algorithm ∈ {SHA-1,SHA-256,SHA-512}.
//   - decodeBase32(input) — strict RFC 4648 (no padding) decoder. Exported so
//     the Entries view can validate user input before save without computing
//     a code.
//   - parseOtpauth(uri) — extracts a base32 secret from an otpauth://totp URI.
//     Throws on unsupported algorithm/digits/period parameters with a
//     human-readable message.
//   - startTotpDisplay(host, secretBase32, opts?) — drives a live row widget:
//     refreshes the code on each period boundary, animates a countdown ring
//     via requestAnimationFrame (or shows a numeric countdown when the user
//     prefers reduced motion), and tears down on stop() or vault:locked.
//
// No DOM coupling in the generator function itself; the display widget is a
// thin orchestrator that keeps the pure code path testable.
//
// Reuses copyWithAutoClear from vault.js for the row's Copy button — the 30s
// clipboard auto-clear is a global behaviour and must not be duplicated here.

import { copyWithAutoClear } from '/js/vault.js';

const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_ALGORITHM = 'SHA-1';

// Map from URI-based algorithm names (SHA1, SHA256, SHA512) to Web Crypto
// algorithm identifiers (SHA-1, SHA-256, SHA-512).
const ALGORITHM_URI_TO_WEB_CRYPTO = {
    'SHA1': 'SHA-1',
    'SHA256': 'SHA-256',
    'SHA512': 'SHA-512',
};

const SUPPORTED_ALGORITHMS = new Set(['SHA-1', 'SHA-256', 'SHA-512']);

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ----- pure functions -----

// Strict RFC 4648 base32 decode, no padding, A–Z + 2–7 only (uppercase).
// User-supplied secrets are normalized to uppercase + whitespace stripped
// before decode; anything outside the alphabet rejects.
export function decodeBase32(input) {
    if (typeof input !== 'string') {
        throw new Error('base32 input must be a string');
    }
    const cleaned = input.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
    if (cleaned.length === 0) {
        throw new Error('base32 input is empty');
    }
    const out = new Uint8Array(Math.floor((cleaned.length * 5) / 8));
    let buffer = 0;
    let bitsLeft = 0;
    let outIndex = 0;
    for (let i = 0; i < cleaned.length; i++) {
        const ch = cleaned[i];
        const idx = BASE32_ALPHABET.indexOf(ch);
        if (idx < 0) {
            throw new Error(`invalid base32 character: '${ch}'`);
        }
        buffer = (buffer << 5) | idx;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            out[outIndex++] = (buffer >> bitsLeft) & 0xff;
        }
    }
    // RFC 4648 requires that any trailing bits be zero. Reject otherwise so we
    // don't silently accept a corrupted secret.
    if (bitsLeft > 0 && (buffer & ((1 << bitsLeft) - 1)) !== 0) {
        throw new Error('base32 input has non-zero trailing bits');
    }
    return out.subarray(0, outIndex);
}

// 8-byte big-endian counter from `seconds // period`. Uses a DataView pair of
// 32-bit writes because JavaScript bitwise ops are 32-bit; the high half is
// always zero for any plausible Unix time but we write it explicitly.
function counterBytes(unixSeconds, period) {
    const counter = Math.floor(unixSeconds / period);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    const high = Math.floor(counter / 0x1_0000_0000);
    const low = counter >>> 0;
    view.setUint32(0, high, false);
    view.setUint32(4, low, false);
    return new Uint8Array(buf);
}

// HMAC-SHA-1/SHA-256/SHA-512 of `message` with `keyBytes` via Web Crypto. Returns the
// MAC as a Uint8Array (20, 32, or 64 bytes depending on the algorithm).
async function hmacSign(keyBytes, message, algorithm = 'SHA-1') {
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: algorithm },
        false,
        ['sign'],
    );
    const sig = await crypto.subtle.sign('HMAC', key, message);
    return new Uint8Array(sig);
}

// RFC 4226 §5.3 dynamic truncation, then mod 10^digits and zero-pad.
function truncate(hmac, digits) {
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    const mod = 10 ** digits;
    return String(code % mod).padStart(digits, '0');
}

// Compute the current TOTP. Production calls pass no options — the defaults
// match RFC 6238 over SHA-1 / 30s / 6-digit. `when` is exposed so the display
// widget can pre-compute the next-boundary code if needed; it is not used in
// normal operation. algorithm ∈ {SHA-1, SHA-256, SHA-512}.
export async function generateTotp(secretBase32, options = {}) {
    const period = options.period ?? DEFAULT_PERIOD;
    const digits = options.digits ?? DEFAULT_DIGITS;
    const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
    if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
        throw new Error(`unsupported algorithm '${algorithm}'; use SHA-1, SHA-256, or SHA-512`);
    }
    if (digits !== 6) {
        throw new Error('only 6-digit codes are supported');
    }
    if (period !== 30) {
        throw new Error('only a 30-second period is supported');
    }
    const secretBytes = decodeBase32(secretBase32);
    if (secretBytes.length === 0) {
        throw new Error('decoded secret is empty');
    }
    const whenSeconds = options.when !== undefined
        ? options.when
        : Math.floor(Date.now() / 1000);
    const counter = counterBytes(whenSeconds, period);
    const hmac = await hmacSign(secretBytes, counter, algorithm);
    return truncate(hmac, digits);
}

// Parse an otpauth://totp URI. Extracts the secret param and validates that
// algorithm / digits / period are the v1-supported defaults; rejects anything
// else with a human-readable message. Returns the bare base32 secret string.
export function parseOtpauth(uri) {
    if (typeof uri !== 'string') {
        throw new Error('otpauth URI must be a string');
    }
    let url;
    try {
        url = new URL(uri);
    } catch (_) {
        throw new Error('not a valid URI');
    }
    if (url.protocol !== 'otpauth:') {
        throw new Error('not an otpauth:// URI');
    }
    if (url.host.toLowerCase() !== 'totp') {
        throw new Error('only otpauth://totp/ is supported');
    }
    const secret = url.searchParams.get('secret');
    if (!secret) {
        throw new Error('otpauth URI is missing the secret parameter');
    }
    const rawAlgorithm = (url.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    if (!ALGORITHM_URI_TO_WEB_CRYPTO[rawAlgorithm]) {
        throw new Error('unsupported algorithm; use SHA-1, SHA-256, or SHA-512');
    }
    const digitsParam = url.searchParams.get('digits');
    if (digitsParam !== null && digitsParam !== '6') {
        throw new Error('only 6-digit TOTP codes are supported');
    }
    const periodParam = url.searchParams.get('period');
    if (periodParam !== null && periodParam !== '30') {
        throw new Error('only a 30-second TOTP period is supported');
    }
    return secret;
}

// Format a 6-digit code as "123 456" (3+3 grouped, narrow no-break space U+202F
// so the gap reads as one token to a screen reader). Pure helper.
export function formatCodeForDisplay(code) {
    if (typeof code !== 'string' || code.length !== 6) return code;
    return `${code.slice(0, 3)} ${code.slice(3)}`;
}

// ----- live display widget -----
//
// Drives a single TOTP block in an entry row:
//   - <span class="vault-totp-code"> shows the formatted current code.
//   - <svg class="vault-totp-ring"> animates a stroke-dashoffset countdown
//     each rAF tick. With prefers-reduced-motion the ring's animation is
//     suppressed and a numeric "Ns" readout takes over instead.
//   - <button class="vault-totp-copy"> copies the bare (unformatted) code via
//     copyWithAutoClear so the 30s clipboard-clear matches the password copy.
//
// Code regeneration is scheduled with setTimeout aligned to the next period
// boundary (NOT a 1s polling interval) so we don't drift across long-lived
// sessions and the code rotates on the boundary rather than up-to-1s late.
//
// Returns a stop() function. The caller must invoke stop() when the row is
// removed; the widget also self-tears-down on document 'vault:locked'.
export function startTotpDisplay(host, secretBase32, opts = {}) {
    const period = opts.period ?? DEFAULT_PERIOD;
    const codeEl = host.querySelector('.vault-totp-code');
    const ringEl = host.querySelector('.vault-totp-ring-progress');
    const readoutEl = host.querySelector('.vault-totp-countdown');
    const copyBtn = host.querySelector('.vault-totp-copy');

    // The SVG ring uses pathLength=100 so dashoffset reads as a percentage
    // 0..100 regardless of actual circle circumference. See site.css.
    const RING_LENGTH = 100;

    let stopped = false;
    let regenTimerId = null;
    let countdownTimerId = null;
    let rafId = null;
    let currentBareCode = '';

    const reduceMotion = typeof window !== 'undefined'
        && window.matchMedia
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function setCode(bare) {
        currentBareCode = bare;
        if (codeEl) {
            codeEl.textContent = formatCodeForDisplay(bare);
            codeEl.setAttribute('aria-label', `Current TOTP code ${bare.split('').join(' ')}`);
        }
    }

    function showError(message) {
        currentBareCode = '';
        if (codeEl) {
            codeEl.textContent = '------';
            codeEl.setAttribute('aria-label', 'TOTP code unavailable');
        }
        if (readoutEl) readoutEl.textContent = '';
        if (copyBtn) copyBtn.disabled = true;
        host.dataset.totpError = message;
    }

    function fractionRemaining() {
        const seconds = Date.now() / 1000;
        const elapsed = seconds % period;
        return Math.max(0, Math.min(1, 1 - elapsed / period));
    }

    function updateRingFrame() {
        if (stopped) return;
        if (ringEl) {
            const remaining = fractionRemaining();
            // dashoffset 0 = full ring drawn; RING_LENGTH = empty. Deplete from
            // full to empty over the period.
            ringEl.style.strokeDashoffset = String(RING_LENGTH * (1 - remaining));
        }
        if (readoutEl) {
            const secondsLeft = Math.ceil(period * fractionRemaining());
            readoutEl.textContent = `${secondsLeft}s`;
        }
        rafId = window.requestAnimationFrame(updateRingFrame);
    }

    function updateNumericFallback() {
        if (stopped) return;
        if (readoutEl) {
            const secondsLeft = Math.ceil(period * fractionRemaining());
            readoutEl.textContent = `${secondsLeft}s`;
        }
        // Tick once a second is plenty when motion is reduced. Uses its own
        // timer slot so the period-boundary regen scheduler is not disturbed.
        countdownTimerId = window.setTimeout(updateNumericFallback, 1000);
    }

    async function refreshCodeAndSchedule() {
        if (stopped) return;
        try {
            const bare = await generateTotp(secretBase32);
            setCode(bare);
            if (host.dataset.totpError) delete host.dataset.totpError;
            if (copyBtn) copyBtn.disabled = false;
        } catch (err) {
            showError(err && err.message ? err.message : 'invalid');
            return;
        }
        // Schedule the next regen exactly at the upcoming period boundary so
        // the displayed code rotates on the boundary (not up to 1s late).
        const seconds = Date.now() / 1000;
        const msToNext = (period - (seconds % period)) * 1000;
        regenTimerId = window.setTimeout(refreshCodeAndSchedule, Math.max(50, msToNext));
    }

    function copyCurrentCode() {
        if (!currentBareCode || !copyBtn) return;
        // Bare 6-digit code goes to the clipboard — the formatted "123 456"
        // is presentation only and must not leak the narrow-space into pastes.
        copyWithAutoClear(currentBareCode, copyBtn);
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', copyCurrentCode);
    }

    function stop() {
        if (stopped) return;
        stopped = true;
        if (regenTimerId !== null) {
            window.clearTimeout(regenTimerId);
            regenTimerId = null;
        }
        if (countdownTimerId !== null) {
            window.clearTimeout(countdownTimerId);
            countdownTimerId = null;
        }
        if (rafId !== null) {
            window.cancelAnimationFrame(rafId);
            rafId = null;
        }
        document.removeEventListener('vault:locked', stop);
    }

    document.addEventListener('vault:locked', stop);

    // Kick off both: code-on-boundary and the visual countdown. The countdown
    // path is rAF for smooth motion (or 1s setTimeout for reduced-motion).
    refreshCodeAndSchedule();
    if (reduceMotion) {
        updateNumericFallback();
    } else {
        rafId = window.requestAnimationFrame(updateRingFrame);
    }

    return stop;
}
