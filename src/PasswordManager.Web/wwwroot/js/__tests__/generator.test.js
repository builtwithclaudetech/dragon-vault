// Dragon Vault password generator — pure function tests.
//
// generatePassword uses crypto.getRandomValues which is synchronous and available
// in Node.js/jsdom. All tests exercise the pure core, not the dialog widget.

import { describe, it, expect } from 'vitest';
import { generatePassword } from '/js/generator.js';

const ALL_CLASSES = { upper: true, lower: true, digits: true, symbols: true };

describe('generatePassword — length validation', () => {
    it('generates a password of the requested length', () => {
        const pw = generatePassword(20, ALL_CLASSES);
        expect(pw).toHaveLength(20);
    });

    it('generates a 128-character password when asked', () => {
        const pw = generatePassword(128, ALL_CLASSES);
        expect(pw).toHaveLength(128);
    });

    it('throws for length below 8', () => {
        expect(() => generatePassword(4, ALL_CLASSES)).toThrow('length must be');
    });

    it('throws for length above 128', () => {
        expect(() => generatePassword(200, ALL_CLASSES)).toThrow('length must be');
    });

    it('throws for non-integer length', () => {
        expect(() => generatePassword(12.7, ALL_CLASSES)).toThrow('length must be');
    });
});

describe('generatePassword — character class inclusion', () => {
    it('includes at least one uppercase letter', () => {
        const pw = generatePassword(32, ALL_CLASSES);
        expect(pw).toMatch(/[A-Z]/);
    });

    it('includes at least one lowercase letter', () => {
        const pw = generatePassword(32, ALL_CLASSES);
        expect(pw).toMatch(/[a-z]/);
    });

    it('includes at least one digit', () => {
        const pw = generatePassword(32, ALL_CLASSES);
        expect(pw).toMatch(/[0-9]/);
    });

    it('includes at least one symbol', () => {
        const pw = generatePassword(32, ALL_CLASSES);
        expect(pw).toMatch(/[!@#$%^&*()\-_=+\[\]{};:,.<>?/]/);
    });

    it('produces only uppercase characters when only that class is selected', () => {
        for (let i = 0; i < 10; i++) {
            const pw = generatePassword(16, {
                upper: true,
                lower: false,
                digits: false,
                symbols: false,
            });
            expect(pw).toMatch(/^[A-Z]+$/);
            expect(pw).toHaveLength(16);
        }
    });
});

describe('generatePassword — edge cases', () => {
    it('throws when no character class is selected', () => {
        expect(() =>
            generatePassword(16, {
                upper: false,
                lower: false,
                digits: false,
                symbols: false,
            }),
        ).toThrow('at least one character class');
    });

    it('produces different values on successive calls (randomness)', () => {
        const results = new Set();
        for (let i = 0; i < 5; i++) {
            results.add(generatePassword(12, ALL_CLASSES));
        }
        // With 5 draws from a 12-char password, duplicates are astronomically unlikely
        expect(results.size).toBe(5);
    });
});
