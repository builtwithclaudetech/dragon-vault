// Phase D — Settings / Passkeys page module. Wires the buttons to webauthn.js +
// crypto.js. Visual polish is web-designer-ux's territory; the goal here is correct
// orchestration:
//
//   - On load: fetch + render the credentials list.
//   - "Register" opens a modal that asks for nickname + master password. The master
//     password is needed locally to re-derive the raw encryption-key bytes (Argon2id
//     KDF) so we can wrap them under the freshly-generated passkey-derived key.
//   - "Revoke" hits DELETE /api/webauthn/credentials/{id}.

import {
    listCredentials, revokeCredential, registerPasskey,
} from '/js/webauthn.js';
import {
    getRawEncryptionKeyForPasskeyWrap,
    getJson,
    b64Decode,
} from '/js/crypto.js';

const root = document.querySelector('section[data-user-id]');
const userId = root ? root.dataset.userId : '';
const listStatus = document.getElementById('passkey-status');
const listBody = document.getElementById('passkey-list-body');
const registerButton = document.getElementById('register-passkey-button');

const dialog = document.getElementById('register-passkey-dialog');
const dialogStatus = document.getElementById('register-status');
const nicknameInput = document.getElementById('register-nickname');
const masterPwInput = document.getElementById('register-master-password');
const confirmButton = document.getElementById('register-confirm');
const cancelButton = document.getElementById('register-cancel');

function renderList(creds) {
    if (!creds || creds.length === 0) {
        listBody.innerHTML = '<tr><td colspan="6">No passkeys registered yet.</td></tr>';
        return;
    }
    listBody.innerHTML = '';
    for (const c of creds) {
        const tr = document.createElement('tr');
        tr.dataset.id = c.id;
        const created = c.createdUtc ? new Date(c.createdUtc).toLocaleString() : '';
        const lastUsed = c.lastUsedUtc ? new Date(c.lastUsedUtc).toLocaleString() : '—';
        tr.innerHTML = `
            <td>${escapeHtml(c.nickname || '(unnamed)')}</td>
            <td>${escapeHtml(c.wrapMethod)}</td>
            <td>${escapeHtml(c.transports || '—')}</td>
            <td>${created}</td>
            <td>${lastUsed}</td>
            <td><button type="button" class="revoke-btn" data-id="${c.id}">Revoke</button></td>
        `;
        listBody.appendChild(tr);
    }
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function refreshList() {
    listStatus.textContent = 'Loading…';
    try {
        const creds = await listCredentials();
        listStatus.textContent = '';
        renderList(creds);
    } catch (err) {
        listStatus.textContent = `Could not load credentials: ${err.message || err}`;
    }
}

listBody.addEventListener('click', async (ev) => {
    const btn = ev.target && ev.target.closest && ev.target.closest('.revoke-btn');
    if (!btn) return;
    const id = btn.dataset.id;
    if (!id) return;
    if (!window.confirm('Revoke this passkey? It will no longer be able to unlock the vault.')) return;
    btn.disabled = true;
    try {
        await revokeCredential(id);
        await refreshList();
    } catch (err) {
        listStatus.textContent = `Revoke failed: ${err.message || err}`;
        btn.disabled = false;
    }
});

registerButton.addEventListener('click', () => {
    dialogStatus.textContent = '';
    nicknameInput.value = '';
    masterPwInput.value = '';
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
});

cancelButton.addEventListener('click', () => {
    if (typeof dialog.close === 'function') dialog.close('cancel');
    else dialog.removeAttribute('open');
});

confirmButton.addEventListener('click', async () => {
    const masterPassword = masterPwInput.value;
    if (!masterPassword) {
        dialogStatus.textContent = 'Master password required.';
        return;
    }
    confirmButton.disabled = true;
    cancelButton.disabled = true;
    dialogStatus.textContent = 'Deriving key…';

    let rawKey = null;
    try {
        // Pull the user's KDF parameters + salt from the server (no secrets).
        const kdfInfo = await getJson('/api/account/kdf-info');
        rawKey = await getRawEncryptionKeyForPasskeyWrap({
            masterPassword,
            kdfSalt: b64Decode(kdfInfo.kdfSalt),
            kdfIterations: kdfInfo.kdfIterations,
            kdfMemoryKb: kdfInfo.kdfMemoryKb,
            kdfParallelism: kdfInfo.kdfParallelism,
            kdfOutputBytes: kdfInfo.kdfOutputBytes,
        });

        dialogStatus.textContent = 'Touch the authenticator to register…';
        const result = await registerPasskey({
            nickname: nicknameInput.value.trim() || null,
            encryptionKeyRawBytes: rawKey,    // registerPasskey zeros this on return
            userId,
        });
        rawKey = null;   // already zeroed
        dialogStatus.textContent = `Registered (${result.wrapMethod}). Redirecting…`;
        if (typeof dialog.close === 'function') dialog.close('confirm');
        else dialog.removeAttribute('open');
        window.location.href = '/Vault/Entries';
    } catch (err) {
        dialogStatus.textContent = `Registration failed: ${err.message || err}`;
        if (rawKey) { try { rawKey.fill(0); } catch (_) { /* */ } }
    } finally {
        confirmButton.disabled = false;
        cancelButton.disabled = false;
        masterPwInput.value = '';
    }
});

// Kick off the initial list load.
refreshList();
