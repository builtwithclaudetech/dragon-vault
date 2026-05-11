// HIBP k-anonymity check — pure function tests.
//
// SHA-1("password") = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
//   prefix = "5BAA6" (first 5 uppercase hex chars)
//   suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8" (remaining 35 chars)
//
// All network access is mocked via vi.stubGlobal('fetch', ...).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkHibpBreach } from '/js/hibp.js';

describe('checkHibpBreach', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it('returns no-breach for empty password without network call', async () => {
        const result = await checkHibpBreach('');
        expect(result).toEqual({ found: false, count: 0, error: false });
    });

    it('sends only the 5-character SHA-1 prefix to HIBP', async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            text: () => Promise.resolve(''),
        });
        vi.stubGlobal('fetch', fetchMock);

        await checkHibpBreach('password');
        const calledUrl = fetchMock.mock.calls[0][0];
        expect(calledUrl).toContain('api.pwnedpasswords.com');
        expect(calledUrl).toContain('5BAA6');
    });

    it('returns found=true when suffix matches a response line', async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            text: () =>
                Promise.resolve(
                    [
                        '00000000000000000000000000000000000:3',
                        '1E4C9B93F3F0682250B6CF8331B7EE68FD8:100500',
                        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1',
                    ].join('\n'),
                ),
        });
        vi.stubGlobal('fetch', fetchMock);

        const result = await checkHibpBreach('password');
        expect(result).toEqual({ found: true, count: 100500, error: false });
    });

    it('returns found=false when no suffix in response matches', async () => {
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            text: () =>
                Promise.resolve('11111111111111111111111111111111111:42\n'),
        });
        vi.stubGlobal('fetch', fetchMock);

        const result = await checkHibpBreach('correcthorsebatterystaple');
        expect(result).toEqual({ found: false, count: 0, error: false });
    });

    it('returns error=true on network failure', async () => {
        vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network failure')));

        const result = await checkHibpBreach('password');
        expect(result).toEqual({ found: false, count: 0, error: true });
    });

    it('returns error=true on non-2xx HTTP response', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue({ ok: false, status: 500 }),
        );

        const result = await checkHibpBreach('password');
        expect(result).toEqual({ found: false, count: 0, error: true });
    });

    it('handles AbortSignal timeout gracefully', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockRejectedValue(new DOMException('The operation was aborted', 'AbortError')),
        );

        const result = await checkHibpBreach('password', {
            signal: new AbortController().signal,
        });
        expect(result).toEqual({ found: false, count: 0, error: true });
    });
});
