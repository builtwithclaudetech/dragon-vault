// Dragon Vault TOTP — pure function tests.
//
// Uses RFC 4226 Appendix D test vectors (HOTP) via the `when` parameter which sets
// the Unix-time counter: counter = floor(when / 30). So when=0 → counter 0, when=30
// → counter 1, etc.
//
// Test key: 20 zero-based bytes "12345678901234567890" → base32
// "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
//
// NOTE: As of OQ-03 resolution, SHA-256 and SHA-512 are also supported (in
// addition to SHA-1). The code now uses SUPPORTED_ALGORITHMS and hmacSign.

import { describe, it, expect } from 'vitest';
import { generateTotp, decodeBase32, parseOtpauth, formatCodeForDisplay } from '/js/totp.js';

const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

const TEST_SECRET_16BYTE = 'JBSWY3DPEHPK3PXP';

describe('decodeBase32', () => {
    it('decodes a valid 20-byte base32 secret', () => {
        const bytes = decodeBase32(TEST_SECRET);
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBe(20);
        // First char "1" = ASCII 0x31
        expect(bytes[0]).toBe(0x31);
        // Last char "0" = ASCII 0x30
        expect(bytes[19]).toBe(0x30);
    });

    it('throws on empty input', () => {
        expect(() => decodeBase32('')).toThrow('empty');
    });

    it('throws on input with invalid characters', () => {
        expect(() => decodeBase32('GEZDGNBVGY3TQ0JQ')).toThrow('invalid base32 character');
    });

    it('throws on non-string input', () => {
        expect(() => decodeBase32(123)).toThrow('must be a string');
    });

    it('strips whitespace and padding before decoding', () => {
        const withWhitespace = 'GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ';
        const bytes = decodeBase32(withWhitespace);
        expect(bytes.length).toBe(20);
    });
});

describe('generateTotp', () => {
    it('generates expected TOTP for HOTP counter 0 (when=0)', async () => {
        const code = await generateTotp(TEST_SECRET, { when: 0 });
        // RFC 4226 Appendix D: counter 0 = 755224
        expect(code).toBe('755224');
    });

    it('generates expected TOTP for HOTP counter 1 (when=30)', async () => {
        const code = await generateTotp(TEST_SECRET, { when: 30 });
        expect(code).toBe('287082');
    });

    it('generates expected TOTP for HOTP counter 2 (when=60)', async () => {
        const code = await generateTotp(TEST_SECRET, { when: 60 });
        expect(code).toBe('359152');
    });

    it('generates expected TOTP for HOTP counter 3 (when=90)', async () => {
        const code = await generateTotp(TEST_SECRET, { when: 90 });
        expect(code).toBe('969429');
    });

    it('accepts SHA-256 and produces a 6-digit code', async () => {
        const code = await generateTotp(TEST_SECRET_16BYTE, {
            when: 0,
            algorithm: 'SHA-256',
        });
        expect(code).toMatch(/^\d{6}$/);
    });

    it('SHA-256 produces a different code than SHA-1 for same input', async () => {
        const codeSha1 = await generateTotp(TEST_SECRET_16BYTE, { when: 0, algorithm: 'SHA-1' });
        const codeSha256 = await generateTotp(TEST_SECRET_16BYTE, {
            when: 0,
            algorithm: 'SHA-256',
        });
        expect(codeSha256).not.toBe(codeSha1);
    });

    it('accepts SHA-512 and produces a 6-digit code', async () => {
        const code = await generateTotp(TEST_SECRET_16BYTE, {
            when: 0,
            algorithm: 'SHA-512',
        });
        expect(code).toMatch(/^\d{6}$/);
    });

    it('rejects an unsupported algorithm name', async () => {
        await expect(
            generateTotp(TEST_SECRET, { algorithm: 'MD5' }),
        ).rejects.toThrow('unsupported algorithm');
    });

    it('rejects non-6-digit code parameter', async () => {
        await expect(
            generateTotp(TEST_SECRET, { digits: 8 }),
        ).rejects.toThrow('only 6-digit');
    });

    it('rejects non-30-second period parameter', async () => {
        await expect(
            generateTotp(TEST_SECRET, { period: 60 }),
        ).rejects.toThrow('only a 30-second period');
    });

    it('produces a 6-digit zero-padded string for current time', async () => {
        const code = await generateTotp(TEST_SECRET);
        expect(code).toMatch(/^\d{6}$/);
    });
});

describe('parseOtpauth', () => {
    it('extracts the secret from a valid otpauth URI', () => {
        const secret = parseOtpauth(
            'otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
        );
        expect(secret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('extracts the secret from a URI with SHA-256 algorithm', () => {
        const secret = parseOtpauth(
            'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256',
        );
        expect(secret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('throws for a non-otpauth protocol', () => {
        expect(() => parseOtpauth('https://example.com')).toThrow('not an otpauth://');
    });

    it('throws when the secret parameter is missing', () => {
        expect(() => parseOtpauth('otpauth://totp/Example:alice?issuer=Example')).toThrow(
            'missing the secret',
        );
    });

    it('throws for non-string input', () => {
        expect(() => parseOtpauth(42)).toThrow('must be a string');
    });

    it('throws for an unsupported algorithm parameter', () => {
        expect(() =>
            parseOtpauth(
                'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
            ),
        ).toThrow('unsupported algorithm');
    });
});

describe('formatCodeForDisplay', () => {
    it('formats "123456" as "123\\u202F456" (narrow no-break space)', () => {
        const result = formatCodeForDisplay('123456');
        // U+202F is the narrow no-break space
        expect(result).toBe('123 456');
    });

    it('returns non-6-digit input unchanged', () => {
        expect(formatCodeForDisplay('abc')).toBe('abc');
        expect(formatCodeForDisplay('12345')).toBe('12345');
        expect(formatCodeForDisplay('1234567')).toBe('1234567');
    });
});
