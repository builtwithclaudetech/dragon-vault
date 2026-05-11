// Dragon Vault entry CRUD — encrypt/decrypt round-trip and clipboard tests.
//
// The /js/crypto.js module is mocked to replace only the stateful/network parts
// (getEncryptionKey, getJson, postJson, xsrfToken) while keeping the real
// aesGcmEncrypt/aesGcmDecrypt implementations so we can test a genuine round-trip.
//
// NOTE: vi.mock factory functions are hoisted above all imports, so references to
// module-level variables must use vi.hoisted() to be available at hoist time.

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';

// ---- hoisted mocks ----
// vi.hoisted() returns values that survive the hoisting so the mock factory can
// reference them.

const { mockGetEncryptionKey, mockGetJson, mockPostJson, mockXsrfToken } = vi.hoisted(
    () => ({
        mockGetEncryptionKey: vi.fn(),
        mockGetJson: vi.fn(),
        mockPostJson: vi.fn(),
        mockXsrfToken: vi.fn(() => 'test-xsrf-token'),
    }),
);

vi.mock('/js/crypto.js', async (importOriginal) => {
    const mod = await importOriginal();
    return {
        ...mod,
        getEncryptionKey: mockGetEncryptionKey,
        getJson: mockGetJson,
        postJson: mockPostJson,
        xsrfToken: mockXsrfToken,
    };
});

// ---- imports (after mock) ----

import {
    encryptAndCreateEntry,
    loadAndDecryptEntries,
    copyWithAutoClear,
    cancelClipboardAutoClear,
} from '/js/vault.js';

import * as crypto from '/js/crypto.js';

// ---- helpers ----

function enc(str) {
    return new TextEncoder().encode(str);
}

function aad(entryId, label) {
    const idBytes = enc(entryId);
    const labelBytes = enc(label);
    const out = new Uint8Array(idBytes.length + labelBytes.length);
    out.set(idBytes, 0);
    out.set(labelBytes, idBytes.length);
    return out;
}

// ---- setup ----

let testKey;

beforeAll(async () => {
    // Generate a real AES-GCM key for the round-trip tests. Node.js 24 provides
    // globalThis.crypto.subtle via the jsdom patch in Vitest.
    testKey = await globalThis.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false, // non-extractable — matches production
        ['encrypt', 'decrypt'],
    );
});

beforeEach(() => {
    vi.clearAllMocks();
    mockGetEncryptionKey.mockReturnValue(testKey);
});

afterEach(() => {
    cancelClipboardAutoClear();
});

// ---- encrypt / decrypt round-trip ----

describe('encrypt / decrypt round-trip', () => {
    it('decrypts an entry name that was encrypted with the same key', async () => {
        const entryId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
        const plainName = 'My Vault Entry';

        // Use the real crypto functions to create the server-side payload
        const namePayload = await crypto.aesGcmEncrypt(
            testKey,
            enc(plainName),
            aad(entryId, 'entry-name-v1'),
        );

        const serverEntries = [
            {
                id: entryId,
                name: {
                    ciphertext: crypto.b64Encode(namePayload.ciphertext),
                    iv: crypto.b64Encode(namePayload.iv),
                    authTag: crypto.b64Encode(namePayload.authTag),
                },
                tags: null,
                fields: [],
                rowVersion: 'v1',
                createdUtc: '2026-01-01T00:00:00Z',
                updatedUtc: '2026-01-01T00:00:00Z',
            },
        ];

        mockGetJson.mockResolvedValue(serverEntries);

        const entries = await loadAndDecryptEntries();
        expect(entries).toHaveLength(1);
        expect(entries[0].name).toBe(plainName);
        expect(entries[0].id).toBe(entryId);
    });

    it('decrypts entry fields with correct AAD per field kind', async () => {
        const entryId = 'b2c3d4e5-f6a7-8901-bcde-f12345678901';
        const plainUsername = 'alice';
        const plainPassword = 's3cret!';

        const usernamePayload = await crypto.aesGcmEncrypt(
            testKey,
            enc(plainUsername),
            aad(entryId, 'username'),
        );
        const passwordPayload = await crypto.aesGcmEncrypt(
            testKey,
            enc(plainPassword),
            aad(entryId, 'password'),
        );

        // Build server response with the encrypted fields
        const namePayload = await crypto.aesGcmEncrypt(
            testKey,
            enc('Test'),
            aad(entryId, 'entry-name-v1'),
        );

        const serverEntries = [
            {
                id: entryId,
                name: {
                    ciphertext: crypto.b64Encode(namePayload.ciphertext),
                    iv: crypto.b64Encode(namePayload.iv),
                    authTag: crypto.b64Encode(namePayload.authTag),
                },
                tags: null,
                fields: [
                    {
                        id: 'f1',
                        fieldKind: 'username',
                        key: null,
                        value: {
                            ciphertext: crypto.b64Encode(usernamePayload.ciphertext),
                            iv: crypto.b64Encode(usernamePayload.iv),
                            authTag: crypto.b64Encode(usernamePayload.authTag),
                        },
                        sortOrder: 0,
                    },
                    {
                        id: 'f2',
                        fieldKind: 'password',
                        key: null,
                        value: {
                            ciphertext: crypto.b64Encode(passwordPayload.ciphertext),
                            iv: crypto.b64Encode(passwordPayload.iv),
                            authTag: crypto.b64Encode(passwordPayload.authTag),
                        },
                        sortOrder: 1,
                    },
                ],
                rowVersion: 'v1',
                createdUtc: '2026-01-01T00:00:00Z',
                updatedUtc: '2026-01-01T00:00:00Z',
            },
        ];

        mockGetJson.mockResolvedValue(serverEntries);

        const entries = await loadAndDecryptEntries();
        expect(entries).toHaveLength(1);
        expect(entries[0].fields).toHaveLength(2);
        expect(entries[0].fields[0].value).toBe(plainUsername);
        expect(entries[0].fields[1].value).toBe(plainPassword);
    });

    it('encryptAndCreateEntry posts encrypted payload to the server', async () => {
        mockPostJson.mockResolvedValue({
            ok: true,
            status: 201,
            json: async () => ({ id: 'new-uuid', rowVersion: 'v2' }),
        });

        const result = await encryptAndCreateEntry({
            name: 'New Entry',
            tags: '',
            fields: [
                { fieldKind: 'username', value: 'bob', sortOrder: 0 },
                { fieldKind: 'password', value: 'hunter2', sortOrder: 1 },
            ],
        });

        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('rowVersion', 'v2');
        expect(mockPostJson).toHaveBeenCalledWith(
            '/api/vault/entries',
            expect.objectContaining({ id: expect.any(String) }),
        );
    });
});

// ---- vault-locked errors ----

describe('vault-locked guard', () => {
    it('encryptAndCreateEntry throws when vault is locked', async () => {
        mockGetEncryptionKey.mockReturnValue(null);
        await expect(
            encryptAndCreateEntry({ name: 'x', fields: [] }),
        ).rejects.toThrow('Vault is locked');
    });

    it('loadAndDecryptEntries throws when vault is locked', async () => {
        mockGetEncryptionKey.mockReturnValue(null);
        mockGetJson.mockResolvedValue([
            {
                id: 'x',
                name: { ciphertext: '', iv: '', authTag: '' },
                fields: [],
                rowVersion: 'v1',
            },
        ]);
        await expect(loadAndDecryptEntries()).rejects.toThrow('Vault is locked');
    });
});

// ---- clipboard ----

describe('copyWithAutoClear', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        // jsdom does not provide navigator.clipboard; stub it.
        vi.stubGlobal('navigator', {
            clipboard: {
                writeText: vi.fn().mockResolvedValue(undefined),
            },
        });
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('writes the given text to the clipboard', async () => {
        const ok = await copyWithAutoClear('secret123');
        expect(ok).toBe(true);
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('secret123');
    });

    it('clears the clipboard after the configured delay', async () => {
        await copyWithAutoClear('secret456');
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('secret456');

        vi.advanceTimersByTime(30000);
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('');
    });

    it('returns false when clipboard write fails', async () => {
        vi.stubGlobal('navigator', {
            clipboard: {
                writeText: vi.fn().mockRejectedValue(new Error('Permission denied')),
            },
        });
        const ok = await copyWithAutoClear('secret789');
        expect(ok).toBe(false);
    });

    it('returns false for empty text', async () => {
        const ok = await copyWithAutoClear('');
        expect(ok).toBe(false);
    });

    it('cancels a prior timer on a second copy call (restart window)', async () => {
        await copyWithAutoClear('first');
        await copyWithAutoClear('second');
        // Only 15s of the original 30s have passed — the second call should have
        // cancelled the first timer. Advance by 20s: < 30s so if the first timer
        // were still active it would fire, clearing the clipboard to ''.
        vi.advanceTimersByTime(20000);
        // The second timer is still counting: 10s remaining. Nothing should have
        // been cleared yet.
        expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2); // the two copies

        vi.advanceTimersByTime(10000); // second timer expires
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('');
        expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(3); // +clear
    });
});
