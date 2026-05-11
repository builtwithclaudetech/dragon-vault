// Dragon Vault entry CRUD module. ES module. No framework.
//
// Owns encrypt-on-write / decrypt-on-read for /api/vault/entries (Phase F, REQ-027..031).
// The server is a relay for ciphertext only (see VaultApiController) — every plaintext
// string passes through aesGcmEncrypt/Decrypt with an AAD that binds {entryId, label}.
//
// AAD scheme (must match the server's stored ciphertext over a write/read round-trip):
//   - Entry name:                  utf8(entryId) || utf8("entry-name-v1")
//   - Entry tags:                  utf8(entryId) || utf8("entry-tags-v1")
//   - Well-known field value:      utf8(entryId) || utf8(fieldKind)
//                                  fieldKind ∈ {username,password,url,notes,totp_secret}
//   - Custom field key (display):  utf8(entryId) || utf8("custom-key")
//   - Custom field value:          utf8(entryId) || utf8("custom")
//
// The userId is NOT in the AAD here — the encryption key itself is per-user (derived from
// the master password) so cross-user replay is already structurally prevented at the key
// boundary. Including entryId blocks intra-user row-swap.

import {
    aesGcmEncrypt,
    aesGcmDecrypt,
    b64Encode,
    b64Decode,
    getEncryptionKey,
    postJson,
    getJson,
    xsrfToken,
} from '/js/crypto.js';

// ----- helpers -----

function encText(str) {
    return new TextEncoder().encode(str ?? '');
}

function aad(...parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
}

async function encryptBlob(plaintext, aadBytes) {
    const key = getEncryptionKey();
    if (!key) throw new Error('Vault is locked');
    const pt = encText(plaintext);
    const wrap = await aesGcmEncrypt(key, pt, aadBytes);
    return {
        ciphertext: b64Encode(wrap.ciphertext),
        iv: b64Encode(wrap.iv),
        authTag: b64Encode(wrap.authTag),
    };
}

async function decryptBlob({ ciphertext, iv, authTag }, aadBytes) {
    const key = getEncryptionKey();
    if (!key) throw new Error('Vault is locked');
    const plain = await aesGcmDecrypt(
        key,
        b64Decode(ciphertext),
        b64Decode(iv),
        b64Decode(authTag),
        aadBytes,
    );
    return new TextDecoder().decode(plain);
}

function entryAadBytes(entryIdStr, label) {
    return aad(encText(entryIdStr), encText(label));
}

function fieldValueAadBytes(entryIdStr, fieldKind) {
    // Well-known kinds use the kind itself as the AAD label; custom uses the literal
    // string "custom" so a row-swap from custom to (e.g.) "password" fails the auth tag.
    return aad(encText(entryIdStr), encText(fieldKind));
}

function customKeyAadBytes(entryIdStr) {
    return aad(encText(entryIdStr), encText('custom-key'));
}

// ----- public API -----

// Loads + decrypts every entry for the current user. Returns plain JS objects suitable
// for direct rendering. Throws on network or decryption failure (caller should surface
// a generic "vault load failed" message — Phase G adds richer status UI).
export async function loadAndDecryptEntries() {
    const raw = await getJson('/api/vault/entries');
    const out = [];
    for (const e of raw) {
        out.push(await decryptEntry(e));
    }
    return out;
}

async function decryptEntry(serverEntry) {
    const id = serverEntry.id;
    const name = await decryptBlob(serverEntry.name, entryAadBytes(id, 'entry-name-v1'));
    let tags = '';
    if (serverEntry.tags) {
        tags = await decryptBlob(serverEntry.tags, entryAadBytes(id, 'entry-tags-v1'));
    }
    const fields = [];
    for (const f of serverEntry.fields ?? []) {
        const value = await decryptBlob(f.value, fieldValueAadBytes(id, f.fieldKind));
        let key = null;
        if (f.fieldKind === 'custom' && f.key) {
            key = f.key;  // OQ-05: plaintext key, no longer encrypted
        }
        fields.push({
            id: f.id,
            fieldKind: f.fieldKind,
            key: key,
            value: value,
            sortOrder: f.sortOrder,
        });
    }
    return {
        id: id,
        name: name,
        tags: tags,
        fields: fields,
        rowVersion: serverEntry.rowVersion,
        createdUtc: serverEntry.createdUtc,
        updatedUtc: serverEntry.updatedUtc,
    };
}

// Encrypt a plain entry shape and POST. plainEntry = { name, tags, fields: [{fieldKind, key?, value, sortOrder}] }
// Returns { id, rowVersion } from the server's response.
export async function encryptAndCreateEntry(plainEntry) {
    if (!getEncryptionKey()) throw new Error('Vault is locked');

    const id = crypto.randomUUID();
    const body = await buildRequestPayload(id, plainEntry);
    body.id = id;

    const res = await postJson('/api/vault/entries', body);
    if (!res.ok) {
        throw new Error(`Create entry failed: ${res.status}`);
    }
    const saved = await res.json();
    return { id: saved.id, rowVersion: saved.rowVersion };
}

// Encrypt + PUT for full replace. Caller provides the id + the rowVersion last seen
// from the server. Returns the new rowVersion.
// OQ-04: `previousPasswordPlain` is the plaintext old password to be stored in history
// (encrypted by this function before sending).
export async function encryptAndUpdateEntry(id, plainEntry, rowVersion, previousPasswordPlain) {
    if (!getEncryptionKey()) throw new Error('Vault is locked');
    if (!rowVersion) throw new Error('rowVersion required for update');

    const body = await buildRequestPayload(id, plainEntry);

    // OQ-04: if the caller provided the previous password, encrypt it and add to payload.
    if (previousPasswordPlain) {
        body.previousPassword = await encryptBlob(previousPasswordPlain, fieldValueAadBytes(id, 'password'));
    }

    const res = await fetch(`/api/vault/entries/${encodeURIComponent(id)}`, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'RequestVerificationToken': xsrfToken(),
            'If-Match': rowVersion,
            'Accept': 'application/json',
        },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        throw new Error(`Update entry failed: ${res.status}`);
    }
    const saved = await res.json();
    return { rowVersion: saved.rowVersion };
}

export async function deleteEntry(id) {
    const res = await fetch(`/api/vault/entries/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: {
            'RequestVerificationToken': xsrfToken(),
            'Accept': 'application/json',
        },
    });
    if (!res.ok && res.status !== 204) {
        throw new Error(`Delete entry failed: ${res.status}`);
    }
}

// ----- clipboard auto-clear (REQ-035) -----
//
// Module-scoped so successive calls from anywhere on the page (any row's copy button,
// Phase H generator, Phase I TOTP) cooperate on a single timer. A second copy
// cancels the prior countdown cleanly — no double-clears, no leaked intervals.
//
// Lifecycle:
//   - copyWithAutoClear(text, button?) writes `text` to the clipboard, kicks off a
//     30s countdown (rendered into `button` if supplied), and at expiry overwrites
//     the clipboard with an empty string.
//   - cancelClipboardAutoClear() stops the active timer without touching the
//     clipboard. Used on lock/navigation so we don't try to clear a clipboard that
//     might belong to a different app by then.
//
// Why a single global timer (not one-per-button):
//   The clipboard itself is global. If two buttons each ran a 30s timer, the second
//   copy's countdown would race with the first's clear() — leaking the second
//   secret early. Coalescing onto one timer matches the resource being managed.

export const CLIPBOARD_CLEAR_MS = 30_000;

let _clipTimerId = null;
let _clipIntervalId = null;
let _clipButton = null;
let _clipButtonOriginalLabel = '';

function clearClipboardCountdownUi() {
    if (_clipIntervalId !== null) {
        clearInterval(_clipIntervalId);
        _clipIntervalId = null;
    }
    if (_clipButton) {
        _clipButton.textContent = _clipButtonOriginalLabel;
        _clipButton.removeAttribute('data-clipboard-active');
        _clipButton = null;
        _clipButtonOriginalLabel = '';
    }
}

export function cancelClipboardAutoClear() {
    if (_clipTimerId !== null) {
        clearTimeout(_clipTimerId);
        _clipTimerId = null;
    }
    clearClipboardCountdownUi();
}

export async function copyWithAutoClear(text, button) {
    if (!text) return false;

    // Cancel any prior countdown before we start a fresh one — second click
    // restarts the 30s window cleanly.
    cancelClipboardAutoClear();

    try {
        await navigator.clipboard.writeText(text);
    } catch (_) {
        return false;
    }

    if (button) {
        _clipButton = button;
        _clipButtonOriginalLabel = button.textContent;
        _clipButton.setAttribute('data-clipboard-active', '');
        let secondsLeft = Math.ceil(CLIPBOARD_CLEAR_MS / 1000);
        button.textContent = `Clears in ${secondsLeft}s`;
        _clipIntervalId = setInterval(() => {
            secondsLeft -= 1;
            if (secondsLeft <= 0) {
                // The timeout below handles the actual clipboard clear; the interval
                // only drives the visible countdown.
                return;
            }
            if (_clipButton) {
                _clipButton.textContent = `Clears in ${secondsLeft}s`;
            }
        }, 1000);
    }

    _clipTimerId = setTimeout(async () => {
        _clipTimerId = null;
        try {
            await navigator.clipboard.writeText('');
        } catch (_) {
            // Best-effort — if the clear fails, the user lost focus and the OS will
            // handle clipboard hygiene. Don't surface an error.
        }
        clearClipboardCountdownUi();
    }, CLIPBOARD_CLEAR_MS);

    return true;
}

// Wire once at module load: when the vault locks (idle, cross-tab, manual),
// drop the timer so we don't try to clear the clipboard after the user has moved
// on. We don't write to the clipboard here — the redirect to /Vault/Unlock will
// fire immediately and the page is going away.
if (typeof document !== 'undefined') {
    document.addEventListener('vault:locked', () => {
        cancelClipboardAutoClear();
    });
}

// Build the wire payload for POST/PUT — same field-by-field shape on both endpoints
// (only the Id field differs: POST carries it in the body; PUT carries it in the route).
async function buildRequestPayload(id, plainEntry) {
    const name = await encryptBlob(plainEntry.name ?? '', entryAadBytes(id, 'entry-name-v1'));
    let tags = null;
    if (plainEntry.tags && plainEntry.tags.length > 0) {
        tags = await encryptBlob(plainEntry.tags, entryAadBytes(id, 'entry-tags-v1'));
    }

    const fields = [];
    const inputFields = plainEntry.fields ?? [];
    for (let i = 0; i < inputFields.length; i++) {
        const f = inputFields[i];
        const value = await encryptBlob(f.value ?? '', fieldValueAadBytes(id, f.fieldKind));
        let key = null;
        if (f.fieldKind === 'custom') {
            key = f.key ?? '';  // OQ-05: plaintext key, no longer encrypted
        }
        fields.push({
            fieldKind: f.fieldKind,
            key: key,
            value: value,
            sortOrder: typeof f.sortOrder === 'number' ? f.sortOrder : i,
        });
    }

    return {
        name: name,
        tags: tags,
        fields: fields,
    };
}
