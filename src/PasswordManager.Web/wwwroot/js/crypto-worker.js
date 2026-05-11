// Argon2id derivation in a dedicated Worker so the ~1s/~64MB derivation does not
// freeze the UI thread on a phone. Loads hash-wasm UMD which inlines the WASM blob
// as base64 — no separate .wasm file fetch required (REQ-053 self-host friendly).
//
// Protocol:
//   main -> worker:  { id, password, salt, iterations, memoryKb, parallelism, outputBytes }
//   worker -> main:  { id, ok: true, key: Uint8Array }   on success (key is transferable)
//   worker -> main:  { id, ok: false, error: string }    on failure
//
// After replying, the worker explicitly clears local references to `password` so the
// plaintext does not linger in the worker heap waiting for a GC pass.

self.importScripts('/js/vendor/hash-wasm.umd.min.js');

self.onmessage = async function (ev) {
    const { id, password, salt, iterations, memoryKb, parallelism, outputBytes } = ev.data || {};
    try {
        if (!self.hashwasm || typeof self.hashwasm.argon2id !== 'function') {
            throw new Error('hash-wasm argon2id not available');
        }
        const result = await self.hashwasm.argon2id({
            password: password,
            salt: salt,                  // Uint8Array
            iterations: iterations,
            memorySize: memoryKb,        // KB
            parallelism: parallelism,
            hashLength: outputBytes,
            outputType: 'binary',        // Uint8Array
        });
        // Transfer the key bytes (zero-copy) and let the main thread import them into
        // a non-extractable CryptoKey. Once transferred, the buffer in the worker is
        // detached and unreadable.
        const key = result instanceof Uint8Array ? result : new Uint8Array(result);
        self.postMessage({ id, ok: true, key }, [key.buffer]);
    } catch (err) {
        self.postMessage({ id, ok: false, error: (err && err.message) || String(err) });
    } finally {
        // Best-effort scrub. The original password Uint8Array was structured-cloned on
        // postMessage entry so we can't reach the main-thread copy from here, but we can
        // overwrite the worker's view to shorten its life in this heap.
        if (password && password.fill) {
            try { password.fill(0); } catch (_) { /* frozen - ignore */ }
        }
    }
};
