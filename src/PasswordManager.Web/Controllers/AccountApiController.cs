using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;
using PasswordManager.Web.Models;

namespace PasswordManager.Web.Controllers;

// JSON API for the master-password lifecycle:
//   POST /api/account/setup          — first-time enrollment (Phase C-only path)
//   GET  /api/account/kdf-info       — used by /Vault/Unlock
//   GET  /api/account/recovery-info  — used by /Account/Recover
//   POST /api/account/rotate-master  — recovery + master-password rotation
//
// All POSTs are anti-forgery-validated. The view emits the request token as a meta tag
// (see Setup / Recover views); the browser fetch wrapper reads it and adds it as the
// "RequestVerificationToken" header configured in Program.cs.
//
// Server NEVER sees the master password, recovery code, or encryption key (REQ-073).
// Validation here is structural only: byte lengths, base64 well-formedness, identity match.
[ApiController]
[Authorize]
[Route("api/account")]
public sealed class AccountApiController : ControllerBase
{
    // Length budgets per design §3.1. Verifier plaintext is 16 bytes; the column is widened
    // to 256 to absorb future scheme changes. Reject anything that would exceed the column
    // or that doesn't match the AES-GCM 12/16 IV/tag contract.
    private const int IvLength = 12;
    private const int AuthTagLength = 16;
    private const int MaxCiphertextLength = 256;
    private const int KdfSaltLength = 16;

    private readonly DragonVaultDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IErrorLogService _errorLog;
    private readonly ILogger<AccountApiController> _logger;

    public AccountApiController(
        DragonVaultDbContext db,
        UserManager<ApplicationUser> userManager,
        IErrorLogService errorLog,
        ILogger<AccountApiController> logger)
    {
        _db = db;
        _userManager = userManager;
        _errorLog = errorLog;
        _logger = logger;
    }

    // REQ-014..017, REQ-073: persist the verifier blob + recovery wrap. The browser has
    // already derived everything we receive; we only validate shape and write.
    //
    // First call also seeds KdfSalt and RecoverySalt — the client picks these so the
    // values are committed atomically with the wrapped material that depends on them.
    [HttpPost("setup")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Setup([FromBody] SetupRequest req, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();

            // Idempotency / replay guard. Once setup completes, the verifier blob is the
            // load-bearing routing flag (REQ-009); writing null back would silently demote
            // the user back to first-sign-in. Reject re-runs explicitly.
            if (user.MasterPasswordVerifierBlob is { Length: > 0 })
            {
                return Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Master password already configured",
                    detail: "Use the recovery flow to rotate the master password.");
            }

            if (!TryDecodeBlob(req.VerifierCiphertext, MaxCiphertextLength, allowEmpty: false, out var verifierCt))
                return ProblemBadRequest("verifierCiphertext");
            if (!TryDecodeBlob(req.VerifierIv, IvLength, allowEmpty: false, out var verifierIv, exact: true))
                return ProblemBadRequest("verifierIv");
            if (!TryDecodeBlob(req.VerifierAuthTag, AuthTagLength, allowEmpty: false, out var verifierTag, exact: true))
                return ProblemBadRequest("verifierAuthTag");
            if (!TryDecodeBlob(req.RecoveryWrappedKey, MaxCiphertextLength, allowEmpty: false, out var rwk))
                return ProblemBadRequest("recoveryWrappedKey");
            if (!TryDecodeBlob(req.RecoveryWrappedKeyIv, IvLength, allowEmpty: false, out var rwkIv, exact: true))
                return ProblemBadRequest("recoveryWrappedKeyIv");
            if (!TryDecodeBlob(req.RecoveryWrappedKeyAuthTag, AuthTagLength, allowEmpty: false, out var rwkTag, exact: true))
                return ProblemBadRequest("recoveryWrappedKeyAuthTag");

            // Salts must already be on the row from the GET /Account/Setup render path.
            // If a developer hits this endpoint without going through the view, surface
            // a 409 rather than overwrite the row with whatever the client hands us.
            if (user.KdfSalt.Length != KdfSaltLength || user.RecoverySalt.Length != KdfSaltLength)
            {
                return Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Setup state missing",
                    detail: "Reload /Account/Setup to regenerate the per-user salts.");
            }

            user.VerifierCiphertext = verifierCt;
            user.VerifierIv = verifierIv;
            user.VerifierAuthTag = verifierTag;
            user.RecoveryWrappedKey = rwk;
            user.RecoveryWrapIv = rwkIv;
            user.RecoveryWrapAuthTag = rwkTag;
            user.MasterPasswordVerifierBlob = verifierCt;  // REQ-009 routing flag.

            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            _logger.LogInformation("Master-password setup completed for {UserId}", user.Id);
            return NoContent();
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("account.setup", ex.Message, ex, ct).ConfigureAwait(false);
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Setup failed");
        }
    }

    // REQ-016: returns everything the unlock page needs to derive + verify. No secrets.
    [HttpGet("kdf-info")]
    public async Task<IActionResult> KdfInfo(CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null)
            {
                return Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Setup not complete",
                    detail: "Complete /Account/Setup before unlocking.");
            }

            var dto = new KdfInfoResponse(
                KdfSalt: Convert.ToBase64String(user.KdfSalt),
                KdfIterations: user.KdfIterations,
                KdfMemoryKb: user.KdfMemoryKb,
                KdfParallelism: user.KdfParallelism,
                KdfOutputBytes: user.KdfOutputBytes,
                VerifierCiphertext: Convert.ToBase64String(user.VerifierCiphertext),
                VerifierIv: Convert.ToBase64String(user.VerifierIv),
                VerifierAuthTag: Convert.ToBase64String(user.VerifierAuthTag));
            return Ok(dto);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("account.kdf-info", ex.Message, ex, ct).ConfigureAwait(false);
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Could not load KDF info");
        }
    }

    // REQ-054: hands the recovery page the salt + wrapped key. The browser derives the
    // recovery wrapping key from the user-typed code, unwraps the encryption key, then
    // POSTs /rotate-master with the new master-password material.
    [HttpGet("recovery-info")]
    public async Task<IActionResult> RecoveryInfo(CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null)
            {
                return Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Setup not complete",
                    detail: "Complete /Account/Setup before recovering.");
            }

            var dto = new RecoveryInfoResponse(
                RecoverySalt: Convert.ToBase64String(user.RecoverySalt),
                KdfIterations: user.KdfIterations,
                KdfMemoryKb: user.KdfMemoryKb,
                KdfParallelism: user.KdfParallelism,
                KdfOutputBytes: user.KdfOutputBytes,
                RecoveryWrappedKey: Convert.ToBase64String(user.RecoveryWrappedKey),
                RecoveryWrappedKeyIv: Convert.ToBase64String(user.RecoveryWrapIv),
                RecoveryWrappedKeyAuthTag: Convert.ToBase64String(user.RecoveryWrapAuthTag));
            return Ok(dto);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("account.recovery-info", ex.Message, ex, ct).ConfigureAwait(false);
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Could not load recovery info");
        }
    }

    // REQ-054: rotate-master.
    //
    //   - Browser already verified the recovery code (the AES-GCM unwrap is the proof —
    //     a wrong code fails the auth tag check and never reaches this endpoint).
    //   - Client picks a NEW KdfSalt and re-derives EncryptionKey under the new master
    //     password. Recovery code is unchanged so RecoverySalt stays put; the wrapped
    //     key is rewrapped under the SAME RecoveryWrappingKey but with a fresh IV.
    //   - Vault entry ciphertext is untouched — we rotate the wrap, not the encryption key.
    //
    // Wait: rotation per design §5.4 actually generates a NEW EncryptionKey (NewKdfSalt +
    // newPw → NewEncryptionKey). The recovery wrap is rewrapped because it carries the
    // NEW EncryptionKey now. Existing entry ciphertext stays valid only if EncryptionKey
    // is unchanged. Re-reading the design: "we re-wrap the KEY, not the data" — so the
    // EncryptionKey is unchanged; the new master password wraps the SAME key. The browser
    // takes the unwrapped EncryptionKey (from recovery), generates a NEW KdfSalt, derives
    // a new MasterWrappingKey from (newMasterPw, newKdfSalt), and uses it to produce a
    // NEW verifier. Recovery wrap stays the same since the wrapped key + recovery code
    // are unchanged. The browser submits all of this here.
    //
    // Server simply persists the new salt + verifier + (possibly new) recovery wrap.
    [HttpPost("rotate-master")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RotateMaster([FromBody] RotateMasterRequest req, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null)
            {
                return Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Setup not complete",
                    detail: "Cannot rotate before initial setup.");
            }

            if (!TryDecodeBlob(req.KdfSalt, KdfSaltLength, allowEmpty: false, out var kdfSalt, exact: true))
                return ProblemBadRequest("kdfSalt");
            if (!TryDecodeBlob(req.VerifierCiphertext, MaxCiphertextLength, allowEmpty: false, out var verifierCt))
                return ProblemBadRequest("verifierCiphertext");
            if (!TryDecodeBlob(req.VerifierIv, IvLength, allowEmpty: false, out var verifierIv, exact: true))
                return ProblemBadRequest("verifierIv");
            if (!TryDecodeBlob(req.VerifierAuthTag, AuthTagLength, allowEmpty: false, out var verifierTag, exact: true))
                return ProblemBadRequest("verifierAuthTag");
            if (!TryDecodeBlob(req.RecoveryWrappedKey, MaxCiphertextLength, allowEmpty: false, out var rwk))
                return ProblemBadRequest("recoveryWrappedKey");
            if (!TryDecodeBlob(req.RecoveryWrappedKeyIv, IvLength, allowEmpty: false, out var rwkIv, exact: true))
                return ProblemBadRequest("recoveryWrappedKeyIv");
            if (!TryDecodeBlob(req.RecoveryWrappedKeyAuthTag, AuthTagLength, allowEmpty: false, out var rwkTag, exact: true))
                return ProblemBadRequest("recoveryWrappedKeyAuthTag");

            user.KdfSalt = kdfSalt;
            user.VerifierCiphertext = verifierCt;
            user.VerifierIv = verifierIv;
            user.VerifierAuthTag = verifierTag;
            user.RecoveryWrappedKey = rwk;
            user.RecoveryWrapIv = rwkIv;
            user.RecoveryWrapAuthTag = rwkTag;
            user.MasterPasswordVerifierBlob = verifierCt;  // Stays non-null per Phase C invariant.

            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            _logger.LogInformation("Master password rotated for {UserId}", user.Id);
            return NoContent();
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("account.rotate-master", ex.Message, ex, ct).ConfigureAwait(false);
            return Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Rotate failed");
        }
    }

    // ----- helpers -----

    private async Task<ApplicationUser?> ResolveCurrentUserAsync()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idClaim, out var id)) return null;
        // TODO: no CT overload in 10.0.0
        return await _userManager.FindByIdAsync(id.ToString()).ConfigureAwait(false);
    }

    private IActionResult ProblemBadRequest(string field) =>
        Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "Validation failed",
            detail: $"Field '{field}' is missing or has the wrong byte length.");

    // Base64 → byte[]. `exact` flag toggles between "exactly maxLength bytes" (IVs, tags,
    // salts) and "at most maxLength bytes" (ciphertext blobs whose plaintext can vary).
    private static bool TryDecodeBlob(string? value, int maxLength, bool allowEmpty, out byte[] bytes, bool exact = false)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(value)) return allowEmpty;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return false;
        }
        if (bytes.Length == 0 && !allowEmpty) return false;
        if (exact ? bytes.Length != maxLength : bytes.Length > maxLength) return false;
        return true;
    }
}
