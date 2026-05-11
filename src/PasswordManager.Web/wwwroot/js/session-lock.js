// Dragon Vault session-lock policy. ES module. No framework.
//
// Owns REQ-018 (15 min idle / tab-hidden > 15 min), REQ-019 ("Lock now"),
// REQ-020 (tab close / reload destroys key), and REQ-081 (BroadcastChannel
// cross-tab coordination).
//
// Design contract (docs/design.md §6):
//   - The encryption key lives only in JS memory inside the per-tab page (crypto.js).
//   - Lock destroys the key reference and routes the UI back to /Vault/Unlock.
//   - Any tab firing lock broadcasts on BroadcastChannel('dragon-vault-lock');
//     receivers wipe their local key. Receiving a lock when already locked is a no-op.
//   - Server is uninvolved: the auth cookie is still valid; the key is purely client.
//
// This module is intentionally framework-free — pure browser globals — so it works
// the same from any page (Unlock, Entries, Settings) and is testable under jsdom.

import { lock as cryptoLock, isUnlocked } from '/js/crypto.js';

// --- constants -------------------------------------------------------------

export const IDLE_TIMEOUT_MS = 15 * 60 * 1000;          // REQ-018
export const BROADCAST_CHANNEL_NAME = 'dragon-vault-lock';
export const LOCK_REDIRECT_PATH = '/Vault/Unlock';

const LOCK_MESSAGE = { type: 'lock' };
const UNLOCK_MESSAGE = { type: 'unlock' };

// User-input events that reset the idle timer. Inclusive list per design §6:
//   "mousemove / keydown / touchstart / pointerdown reset; timer fires on inactivity".
// We add scroll + click + wheel because they're cheap, idempotent, and keep the idle
// timer in sync with what a human would call "active".
const ACTIVITY_EVENTS = [
    'mousemove',
    'mousedown',
    'click',
    'keydown',
    'wheel',
    'scroll',
    'touchstart',
    'pointerdown',
];

// --- module state ----------------------------------------------------------

let _idleTimerId = null;
let _hiddenAt = 0;          // ms timestamp when the tab last went hidden; 0 = visible.
let _channel = null;
let _initialized = false;
let _skipRedirectOnLock = false;    // set by initSessionManagement on /Vault/Unlock

// Indirection seam for tests: lets a test override window/document/BroadcastChannel
// without monkey-patching globals. Real callers leave these alone.
const env = {
    window: typeof window !== 'undefined' ? window : null,
    document: typeof document !== 'undefined' ? document : null,
    BroadcastChannel: typeof BroadcastChannel !== 'undefined' ? BroadcastChannel : null,
    now: () => Date.now(),
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
};

// --- core lock pipeline ----------------------------------------------------

// Centralized lock entry. Idempotent: safe to call when already locked.
//   reason: free-form string used only for the dispatched 'vault:locked' event detail.
//   broadcast: when true, post a lock message on the channel so other tabs follow.
//              Cross-tab receivers pass `broadcast: false` to avoid an echo loop.
//   redirect: when true, navigate to /Vault/Unlock if not already there.
export function performLock({ reason = 'manual', broadcast = true, redirect = true } = {}) {
    const wasUnlocked = isUnlocked();

    cryptoLock();

    if (broadcast) {
        broadcastLock();
    }

    // Surface a DOM event so views (Entries, Settings) can react without polling.
    if (env.document && env.document.dispatchEvent && wasUnlocked) {
        try {
            const evt = new CustomEvent('vault:locked', { detail: { reason } });
            env.document.dispatchEvent(evt);
        } catch (_) {
            // CustomEvent unsupported in some headless contexts — non-fatal.
        }
    }

    if (redirect && !_skipRedirectOnLock && env.window && env.window.location) {
        const path = env.window.location.pathname || '';
        if (!path.startsWith(LOCK_REDIRECT_PATH)) {
            env.window.location.href = LOCK_REDIRECT_PATH;
        }
    }

    return wasUnlocked;
}

// Emit a lock message on the cross-tab channel. Exported for direct callers
// (e.g. unlock handlers wanting to clear stale lock state in sibling tabs).
export function broadcastLock() {
    if (!_channel) return;
    try {
        _channel.postMessage(LOCK_MESSAGE);
    } catch (_) {
        // postMessage can throw if the channel is closed mid-shutdown. Safe to drop.
    }
}

// Optional: notify other tabs that THIS tab unlocked. Per design §6 v1, receiving
// tabs do NOT auto-unlock — they stay on the unlock screen. We still emit the
// message so future versions / instrumentation can observe it.
export function broadcastUnlock() {
    if (!_channel) return;
    try {
        _channel.postMessage(UNLOCK_MESSAGE);
    } catch (_) { /* ignored */ }
}

// --- idle timer ------------------------------------------------------------

function clearIdleTimer() {
    if (_idleTimerId !== null) {
        env.clearTimeout(_idleTimerId);
        _idleTimerId = null;
    }
}

export function resetIdleTimer() {
    clearIdleTimer();
    _idleTimerId = env.setTimeout(() => {
        _idleTimerId = null;
        performLock({ reason: 'idle' });
    }, IDLE_TIMEOUT_MS);
}

function onActivity() {
    // Cheap path on every input event — restart the timer.
    resetIdleTimer();
}

// --- visibility (mobile background > 15 min) -------------------------------

function onVisibilityChange() {
    if (!env.document) return;
    if (env.document.hidden) {
        _hiddenAt = env.now();
        // Don't clear the idle timer here — if a phone backgrounds the tab the
        // timer will likely be paused by the browser anyway, and we re-evaluate
        // on visibility return.
    } else {
        // Coming back to the foreground.
        if (_hiddenAt > 0) {
            const elapsed = env.now() - _hiddenAt;
            _hiddenAt = 0;
            if (elapsed > IDLE_TIMEOUT_MS) {
                performLock({ reason: 'tab-hidden-timeout' });
                return;
            }
        }
        // Returning visible counts as activity — reset the idle clock so the user
        // gets a fresh 15 min window from the moment they came back.
        resetIdleTimer();
    }
}

// --- tab close / reload ----------------------------------------------------

function onUnload() {
    // REQ-020: destroy in-memory key on close/reload. cryptoLock() nulls the
    // module-scoped CryptoKey reference — the page itself is going away, so we
    // skip the redirect/broadcast (they'd race with navigation).
    cryptoLock();
}

// --- cross-tab channel -----------------------------------------------------

function onChannelMessage(ev) {
    const msg = ev && ev.data;
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'lock') {
        // Don't re-broadcast — that would amplify a single user action into a storm.
        performLock({ reason: 'cross-tab', broadcast: false });
    }
    // 'unlock' messages are observed but intentionally not acted on (see design §6).
}

// --- public init -----------------------------------------------------------

// Call once per page load. Safe to call multiple times — second call is a no-op.
export function initSessionManagement(options = {}) {
    if (_initialized) return;

    // Allow the caller (e.g. Unlock view) to opt out of redirect-on-lock so the user
    // doesn't get bounced from the unlock page back to itself in a loop.
    const skipRedirectOnLock = options.skipRedirectOnLock === true;

    if (env.document) {
        for (const evtName of ACTIVITY_EVENTS) {
            // passive:true on touch/scroll keeps mobile scroll perf intact; capture:true
            // catches activity even when an inner element calls stopPropagation.
            env.document.addEventListener(evtName, onActivity, { passive: true, capture: true });
        }
        env.document.addEventListener('visibilitychange', onVisibilityChange);
    }

    if (env.window) {
        // pagehide fires reliably on mobile (iOS Safari/Chrome) where beforeunload
        // does not. Listen to both for desktop + mobile coverage.
        env.window.addEventListener('beforeunload', onUnload);
        env.window.addEventListener('pagehide', onUnload);
    }

    if (env.BroadcastChannel) {
        try {
            _channel = new env.BroadcastChannel(BROADCAST_CHANNEL_NAME);
            _channel.addEventListener('message', onChannelMessage);
        } catch (_) {
            // Some embedded WebViews disable BroadcastChannel. Cross-tab sync is
            // best-effort; idle/explicit lock still work without it.
            _channel = null;
        }
    }

    // Pages already on /Vault/Unlock pass skipRedirectOnLock so a timer-fired lock
    // doesn't bounce them back to themselves. The idle timer still arms — locking
    // is still meaningful (it nulls the key + broadcasts to other tabs) — only the
    // redirect step is suppressed.
    _skipRedirectOnLock = skipRedirectOnLock;

    resetIdleTimer();

    _initialized = true;
}

// --- teardown (tests / hot reload) -----------------------------------------

// Only used by tests and any future SPA route teardown. Removes every listener
// this module attached so a fresh init() starts from a clean slate.
export function _resetForTests() {
    clearIdleTimer();
    if (env.document) {
        for (const evtName of ACTIVITY_EVENTS) {
            env.document.removeEventListener(evtName, onActivity, { capture: true });
        }
        env.document.removeEventListener('visibilitychange', onVisibilityChange);
    }
    if (env.window) {
        env.window.removeEventListener('beforeunload', onUnload);
        env.window.removeEventListener('pagehide', onUnload);
    }
    if (_channel) {
        try { _channel.removeEventListener('message', onChannelMessage); } catch (_) { /* ignored */ }
        try { _channel.close(); } catch (_) { /* ignored */ }
        _channel = null;
    }
    _initialized = false;
    _hiddenAt = 0;
    _skipRedirectOnLock = false;
}

// --- view glue -------------------------------------------------------------

// "Lock now" button handler exposed globally so a Razor view can wire it with a
// single inline `onclick="lockVault()"`. Returns true on a freshly-locked vault,
// false if it was already locked (idempotent).
export function lockVault() {
    return performLock({ reason: 'manual' });
}

// Default export keeps the `import sessionLock from '/js/session-lock.js'` form
// usable from inline page scripts that prefer a single namespace.
export default {
    initSessionManagement,
    lockVault,
    broadcastLock,
    broadcastUnlock,
    resetIdleTimer,
    performLock,
    IDLE_TIMEOUT_MS,
    BROADCAST_CHANNEL_NAME,
    LOCK_REDIRECT_PATH,
};
