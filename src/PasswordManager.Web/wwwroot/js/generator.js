// Dragon Vault password generator (Phase H, REQ-037..040).
//
// Hard rules baked into the contract:
//   - Randomness comes ONLY from crypto.getRandomValues — never Math.random.
//   - The generator dialog is opened by an explicit button click. The new-entry
//     form's password field stays empty until the user clicks "Use this password".
//   - Rejection sampling on every byte → no modulo bias on alphabet sizes.
//   - At least one character class must remain selected; the last-active checkbox
//     disables itself.
//
// Public API:
//   - openGeneratorDialog(onUse) — onUse(password) is invoked when the user
//     clicks "Use this password". Cancel / Esc / backdrop dismiss does nothing.
//   - generatePassword(length, classes) — pure-ish core, exported for testability.
//
// Reuses the Phase G clipboard helper from vault.js for the dialog's Copy button —
// the 30-second clipboard auto-clear is a global behaviour and must not be
// duplicated here.

import { copyWithAutoClear } from '/js/vault.js';

// Character classes. Symbols match REQ-039's stated set. Each class is a string
// (Latin alphabet only — bytes map cleanly to indices via rejection sampling).
const CLASSES = Object.freeze({
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    digits:  '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>?/',
});

const CLASS_ORDER = Object.freeze(['upper', 'lower', 'digits', 'symbols']);

// Rejection-sampled unbiased index into [0, max). For any max ≤ 256 we discard
// bytes that fall in the partial top range so the remaining values are uniform.
function unbiasedIndex(max) {
    if (max <= 0 || max > 256) {
        throw new Error('unbiasedIndex: max must be in (0, 256]');
    }
    const limit = 256 - (256 % max);
    const buf = new Uint8Array(1);
    // Loop is bounded in expectation (worst-case ~2x for max just over 128).
    // crypto.getRandomValues is synchronous and cheap.
    for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % max;
    }
}

// Generate a password of `length` chars drawn from the union of selected
// character classes. Guarantees at least one character from each selected class
// (placed at random positions). Throws on invalid input.
export function generatePassword(length, classes) {
    if (!Number.isInteger(length) || length < 8 || length > 128) {
        throw new Error('length must be an integer in [8, 128]');
    }
    const selected = CLASS_ORDER.filter(name => classes && classes[name]);
    if (selected.length === 0) {
        throw new Error('at least one character class must be selected');
    }
    if (selected.length > length) {
        // Can't honour "at least one of each class" if we have more classes than
        // slots. The UI clamps length ≥ 8 and we have ≤ 4 classes, so this
        // branch is unreachable in practice; guard anyway.
        throw new Error('length must be ≥ number of selected classes');
    }

    const alphabet = selected.map(name => CLASSES[name]).join('');
    const out = new Array(length);

    // Step 1: place one character from each selected class at distinct random
    // slots so the result is guaranteed to satisfy every "include this class"
    // toggle. Fisher-Yates-style slot selection using getRandomValues.
    const slots = pickDistinctSlots(length, selected.length);
    for (let i = 0; i < selected.length; i++) {
        const cls = CLASSES[selected[i]];
        out[slots[i]] = cls[unbiasedIndex(cls.length)];
    }

    // Step 2: fill remaining slots from the union alphabet.
    for (let i = 0; i < length; i++) {
        if (out[i] === undefined) {
            out[i] = alphabet[unbiasedIndex(alphabet.length)];
        }
    }

    return out.join('');
}

function pickDistinctSlots(length, count) {
    // Reservoir-style: shuffle [0..length) then take the first `count`.
    // Length is ≤ 128 so a full shuffle is cheap.
    const arr = new Array(length);
    for (let i = 0; i < length; i++) arr[i] = i;
    for (let i = length - 1; i > 0; i--) {
        const j = unbiasedIndex(i + 1);
        const tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
    return arr.slice(0, count);
}

// ----- dialog -----

const DIALOG_ID = 'generator-modal';

// Build the dialog DOM once and append to <body>. Subsequent opens reuse it.
let dialog = null;
let lengthInput = null;
let lengthReadout = null;
let outputInput = null;
let copyButton = null;
let regenerateButton = null;
let useButton = null;
let cancelButton = null;
let classCheckboxes = null; // Map<className, HTMLInputElement>
let onUseCallback = null;

function ensureDialog() {
    if (dialog) return dialog;

    dialog = document.createElement('dialog');
    dialog.id = DIALOG_ID;
    dialog.setAttribute('aria-labelledby', 'generator-modal-title');

    dialog.innerHTML = `
        <form method="dialog" class="generator-form" novalidate>
            <h2 id="generator-modal-title">Generate password</h2>

            <div class="generator-length">
                <label for="generator-length-input">
                    Length
                    <output id="generator-length-readout" for="generator-length-input">20</output>
                </label>
                <input id="generator-length-input"
                       type="range"
                       min="8"
                       max="128"
                       step="1"
                       value="20"
                       aria-describedby="generator-length-readout" />
            </div>

            <fieldset class="generator-classes">
                <legend>Character classes</legend>
                <label><input type="checkbox" data-class="upper" checked /> Uppercase (A–Z)</label>
                <label><input type="checkbox" data-class="lower" checked /> Lowercase (a–z)</label>
                <label><input type="checkbox" data-class="digits" checked /> Digits (0–9)</label>
                <label><input type="checkbox" data-class="symbols" checked /> Symbols (!@#$…)</label>
            </fieldset>

            <div>
                <label for="generator-output">Generated password</label>
                <input id="generator-output"
                       type="text"
                       readonly
                       autocomplete="off"
                       spellcheck="false"
                       class="generator-output" />
            </div>

            <div class="generator-actions">
                <button id="generator-regenerate" class="btn" type="button">Regenerate</button>
                <button id="generator-copy" class="btn" type="button">Copy</button>
                <span class="generator-actions-spacer" aria-hidden="true"></span>
                <button id="generator-cancel" class="btn" type="button">Cancel</button>
                <button id="generator-use" class="btn btn-primary" type="button">Use this password</button>
            </div>
        </form>
    `;

    document.body.appendChild(dialog);

    lengthInput = dialog.querySelector('#generator-length-input');
    lengthReadout = dialog.querySelector('#generator-length-readout');
    outputInput = dialog.querySelector('#generator-output');
    copyButton = dialog.querySelector('#generator-copy');
    regenerateButton = dialog.querySelector('#generator-regenerate');
    useButton = dialog.querySelector('#generator-use');
    cancelButton = dialog.querySelector('#generator-cancel');

    classCheckboxes = new Map();
    dialog.querySelectorAll('input[type="checkbox"][data-class]').forEach(cb => {
        classCheckboxes.set(cb.dataset.class, cb);
    });

    wireDialogEvents();
    return dialog;
}

function currentClasses() {
    const out = {};
    for (const [name, cb] of classCheckboxes) {
        out[name] = cb.checked;
    }
    return out;
}

function selectedClassCount() {
    let n = 0;
    for (const cb of classCheckboxes.values()) {
        if (cb.checked) n += 1;
    }
    return n;
}

// When only one class remains checked, disable that lone checkbox so the user
// can't uncheck it (REQ-039: at least one class must stay on). Re-enable all
// when more than one is checked.
function syncClassDisabled() {
    const onlyOne = selectedClassCount() === 1;
    for (const cb of classCheckboxes.values()) {
        if (onlyOne && cb.checked) {
            cb.disabled = true;
        } else {
            cb.disabled = false;
        }
    }
}

function regenerate() {
    const length = Number.parseInt(lengthInput.value, 10);
    try {
        outputInput.value = generatePassword(length, currentClasses());
    } catch (_) {
        // Invariant violation (e.g. zero classes selected). syncClassDisabled
        // prevents this state, but if it ever happens, leave the field empty.
        outputInput.value = '';
    }
}

function wireDialogEvents() {
    lengthInput.addEventListener('input', () => {
        lengthReadout.textContent = lengthInput.value;
        regenerate();
    });

    for (const cb of classCheckboxes.values()) {
        cb.addEventListener('change', () => {
            syncClassDisabled();
            regenerate();
        });
    }

    regenerateButton.addEventListener('click', () => {
        regenerate();
    });

    copyButton.addEventListener('click', () => {
        if (outputInput.value) {
            copyWithAutoClear(outputInput.value, copyButton);
            dialog.close();
        }
    });

    useButton.addEventListener('click', () => {
        const value = outputInput.value;
        if (!value) return;
        const cb = onUseCallback;
        onUseCallback = null;
        closeDialog();
        if (typeof cb === 'function') {
            cb(value);
        }
    });

    cancelButton.addEventListener('click', () => {
        onUseCallback = null;
        closeDialog();
    });

    // Esc key dismissal: native <dialog> behaviour fires a 'cancel' event.
    // Treat it as the same as clicking Cancel — drop the callback.
    dialog.addEventListener('cancel', () => {
        onUseCallback = null;
    });

    // Wipe the visible output when the dialog closes — don't leave a generated
    // password sitting in the readonly input across opens.
    dialog.addEventListener('close', () => {
        outputInput.value = '';
    });
}

function closeDialog() {
    if (typeof dialog.close === 'function' && dialog.open) {
        dialog.close();
    } else {
        dialog.removeAttribute('open');
    }
}

// Public entry point.
//
// onUse: function(password: string) — called when user clicks "Use this password".
//        Not called on Cancel, Esc, or backdrop dismiss.
export function openGeneratorDialog(onUse) {
    ensureDialog();
    onUseCallback = typeof onUse === 'function' ? onUse : null;

    // Reset to defaults every open. Length 20, all four classes on.
    lengthInput.value = '20';
    lengthReadout.textContent = '20';
    for (const cb of classCheckboxes.values()) {
        cb.checked = true;
    }
    syncClassDisabled();
    regenerate();

    if (typeof dialog.showModal === 'function') {
        dialog.showModal();
    } else {
        dialog.setAttribute('open', '');
    }

    // Focus + select the readonly output so screen readers announce the
    // generated value and sighted users can copy or regenerate without an
    // extra Tab.
    outputInput.focus();
    outputInput.select();
}

// Wipe the dialog on lock so a stale generated password doesn't survive. The
// dialog's close event already clears the input, but listening for vault:locked
// belt-and-braces against tab-hidden auto-lock with the dialog still open.
if (typeof document !== 'undefined') {
    document.addEventListener('vault:locked', () => {
        if (dialog && dialog.open) {
            onUseCallback = null;
            closeDialog();
        }
    });
}
