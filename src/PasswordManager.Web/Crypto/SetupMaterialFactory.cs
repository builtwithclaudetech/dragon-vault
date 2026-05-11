using System.Security.Cryptography;

namespace PasswordManager.Web.Crypto;

// Small allocator for the random material the Setup page hands the browser.
// The recovery code is generated server-side per ADR-010 so we can guarantee 256-bit
// entropy; the server discards it after returning it once and never logs it.
//
// All randomness comes from RandomNumberGenerator.GetBytes (CSPRNG); never use
// System.Random / Guid.NewGuid for security-relevant material.
public static class SetupMaterialFactory
{
    private const string RecoveryAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private const int RecoveryCodeLength = 32;
    private const int KdfSaltLength = 16;        // REQ-013
    private const int RecoverySaltLength = 16;   // design §3.1

    public static byte[] NewKdfSalt() => RandomNumberGenerator.GetBytes(KdfSaltLength);

    public static byte[] NewRecoverySalt() => RandomNumberGenerator.GetBytes(RecoverySaltLength);

    // 32 chars from a 62-char alphabet via rejection sampling. Rejection sampling is the
    // bias-free way to map uniform random bytes to a non-power-of-two pool; the modulo
    // approach (`b % 62`) skews the distribution toward the first few characters.
    public static string NewRecoveryCode()
    {
        const int alphabetSize = 62;
        // Largest multiple of 62 that fits in a byte: 4 * 62 = 248. Bytes ≥ 248 are rejected.
        const byte cap = 248;
        var output = new char[RecoveryCodeLength];
        Span<byte> buffer = stackalloc byte[1];
        var written = 0;
        while (written < RecoveryCodeLength)
        {
            RandomNumberGenerator.Fill(buffer);
            var b = buffer[0];
            if (b >= cap) continue;
            output[written++] = RecoveryAlphabet[b % alphabetSize];
        }
        return new string(output);
    }
}
