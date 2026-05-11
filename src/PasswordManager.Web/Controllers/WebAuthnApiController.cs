using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;
using PasswordManager.Web.Auth;
using PasswordManager.Web.Models;

namespace PasswordManager.Web.Controllers;

// JSON API for WebAuthn passkey registration + assertion-based unlock.
//
//   POST   /api/webauthn/register/begin           — start registration ceremony
//   POST   /api/webauthn/register/finish          — finalize registration + persist wrap
//   GET    /api/webauthn/credentials              — list user's credentials (no wraps!)
//   DELETE /api/webauthn/credentials/{id}         — revoke a credential
//   POST   /api/webauthn/assert/begin             — start unlock ceremony
//   POST   /api/webauthn/assert/finish            — validate assertion + return wrap
//
// Server NEVER sees the unwrapped EncryptionKey, master password, or recovery code
// (REQ-073). The wrapped-key envelope is server-opaque — the client unwraps it after
// the assertion authenticates which credential was used.
//
// Fido2.AspNet 3.0.1's strongly-typed AuthenticationExtensionsClientInputs lacks
// largeBlob / prf properties, so we construct the WebAuthn options JSON ourselves and
// reach for Fido2 only at the verification step (MakeNewCredentialAsync /
// MakeAssertionAsync). The CredentialId binding in the AAD prevents wrap-row swap
// attacks (design §4.3).
[ApiController]
[Authorize]
[Route("api/webauthn")]
public sealed class WebAuthnApiController : ControllerBase
{
    // AES-GCM contract — same lengths as AccountApiController's verifier blob.
    private const int IvLength = 12;
    private const int AuthTagLength = 16;
    private const int MaxWrappedCiphertextLength = 256;

    // Fixed PRF input — same 32 bytes every time so the wrap key is reproducible from
    // (passkey-secret + this constant). Derived from a project-scoped tag so a future
    // rotation can bump the version without colliding with v1 enrollments.
    private static readonly byte[] PrfInputV1 = SHA256.HashData(
        Encoding.UTF8.GetBytes("dragon-vault-prf-input-v1"));

    private readonly DragonVaultDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IFido2 _fido2;
    private readonly DragonVaultFido2Options _fidoConfig;
    private readonly IWebAuthnChallengeStore _challenges;
    private readonly IErrorLogService _errorLog;
    private readonly ILogger<WebAuthnApiController> _logger;

    public WebAuthnApiController(
        DragonVaultDbContext db,
        UserManager<ApplicationUser> userManager,
        IFido2 fido2,
        DragonVaultFido2Options fidoConfig,
        IWebAuthnChallengeStore challenges,
        IErrorLogService errorLog,
        ILogger<WebAuthnApiController> logger)
    {
        _db = db;
        _userManager = userManager;
        _fido2 = fido2;
        _fidoConfig = fidoConfig;
        _challenges = challenges;
        _errorLog = errorLog;
        _logger = logger;
    }

    // POST /api/webauthn/register/begin
    [HttpPost("register/begin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterBegin(CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();

            // The verifier blob is the canonical "setup completed" flag (Phase B/C invariant).
            // No master password = no encryption key in the browser to wrap = nothing to
            // register a passkey for.
            if (user.MasterPasswordVerifierBlob is null) return SetupNotComplete();

            // Existing credentials become excludeCredentials so the same authenticator can't
            // re-enroll silently.
            var existing = await _db.WebAuthnCredentials
                .Where(c => c.UserId == user.Id)
                .Select(c => new { c.CredentialId, c.Transports })
                .ToListAsync(ct).ConfigureAwait(false);

            var challenge = await _challenges.IssueAsync(user.Id, "register", ct).ConfigureAwait(false);

            // Build the PublicKeyCredentialCreationOptions JSON manually — Fido2.AspNet 3.0.1
            // doesn't model largeBlob / prf in AuthenticationExtensionsClientInputs.
            var options = new JsonObject
            {
                ["challenge"] = Base64Url.Encode(challenge),
                ["rp"] = new JsonObject
                {
                    ["id"] = _fidoConfig.RpId,
                    ["name"] = _fidoConfig.RpName,
                },
                ["user"] = new JsonObject
                {
                    ["id"] = Base64Url.Encode(user.Id.ToByteArray()),
                    ["name"] = user.Email ?? user.UserName ?? user.Id.ToString(),
                    ["displayName"] = user.DisplayName ?? user.Email ?? "Dragon Vault user",
                },
                ["pubKeyCredParams"] = new JsonArray
                {
                    new JsonObject { ["type"] = "public-key", ["alg"] = -7 },    // ES256
                    new JsonObject { ["type"] = "public-key", ["alg"] = -257 },  // RS256
                },
                ["authenticatorSelection"] = new JsonObject
                {
                    ["userVerification"] = "preferred",   // REQ-023 — must NOT be "required"
                    ["residentKey"] = "preferred",
                    ["requireResidentKey"] = false,
                },
                ["attestation"] = "none",
                ["timeout"] = 60_000,
                ["excludeCredentials"] = BuildAllowList(existing.Select(c => (c.CredentialId, c.Transports))),
                ["extensions"] = new JsonObject
                {
                    ["largeBlob"] = new JsonObject { ["support"] = "preferred" },
                    ["prf"] = new JsonObject(),
                },
            };

            return Ok(options);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.register.begin", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Could not start registration");
        }
    }

    // POST /api/webauthn/register/finish
    [HttpPost("register/finish")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterFinish([FromBody] WebAuthnRegisterFinishRequest req, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null) return SetupNotComplete();

            if (req is null || req.AttestationResponse is null || req.WrappedKey is null)
                return ProblemBadRequest("body");

            // Validate wrap-method discriminator + wrap envelope shapes up front.
            if (req.WrappedKey.WrapMethod is not ("largeBlob" or "prf"))
                return ProblemBadRequest("wrappedKey.wrapMethod");
            if (!TryDecodeBlob(req.WrappedKey.Ciphertext, MaxWrappedCiphertextLength, false, out var wrapCt))
                return ProblemBadRequest("wrappedKey.ciphertext");
            if (!TryDecodeBlob(req.WrappedKey.Iv, IvLength, false, out var wrapIv, exact: true))
                return ProblemBadRequest("wrappedKey.iv");
            if (!TryDecodeBlob(req.WrappedKey.AuthTag, AuthTagLength, false, out var wrapTag, exact: true))
                return ProblemBadRequest("wrappedKey.authTag");

            // Deserialize the attestation response to Fido2's strongly-typed shape. The
            // browser-side JSON layout matches WebAuthn spec; Fido2's serializer does the
            // base64url -> byte[] heavy lifting.
            AuthenticatorAttestationRawResponse? raw;
            try
            {
                raw = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(
                    req.AttestationResponse.ToJsonString(),
                    JsonSerializerOptions.Web);
            }
            catch (JsonException)
            {
                return ProblemBadRequest("attestationResponse");
            }
            if (raw is null) return ProblemBadRequest("attestationResponse");

            // Reconstruct the original CredentialCreateOptions used to issue the challenge
            // for Fido2's verification. The library only needs the challenge + the RP/user
            // metadata to validate; the extension fields it doesn't model are fine to omit
            // here because Fido2 doesn't enforce extension presence.
            //
            // We pull the originating challenge bytes out of the assertion's clientDataJSON
            // and consume it from the store. If the challenge is missing or expired or
            // already consumed, this short-circuits to 400.
            var challenge = ExtractChallenge(raw.Response?.ClientDataJson);
            if (challenge is null || !await _challenges.ConsumeAsync(user.Id, challenge, "register", ct).ConfigureAwait(false))
                return ProblemBadRequest("challenge");

            var origOptions = BuildLibraryCreateOptions(user, challenge);

            var existingIds = await _db.WebAuthnCredentials
                .Where(c => c.UserId == user.Id)
                .Select(c => c.CredentialId)
                .ToListAsync(ct).ConfigureAwait(false);

            // Fido2 callback: ensure the credential id isn't already enrolled (anywhere).
            // Single-user scope means the global uniqueness check collapses to "is it on
            // any of THIS user's rows".
            IsCredentialIdUniqueToUserAsyncDelegate isUnique = (args, _) =>
            {
                var clash = existingIds.Any(b => b.AsSpan().SequenceEqual(args.CredentialId.AsSpan()));
                return Task.FromResult(!clash);
            };

            Fido2.CredentialMakeResult result;
            try
            {
                result = await _fido2.MakeNewCredentialAsync(raw, origOptions, isUnique, requestTokenBindingId: null, cancellationToken: ct)
                    .ConfigureAwait(false);
            }
            catch (Fido2VerificationException vex)
            {
                await _errorLog.LogAsync("webauthn.register.verify", vex.Message, vex, ct).ConfigureAwait(false);
                return ProblemBadRequest("attestation");
            }

            if (result.Status != "ok" || result.Result is null)
            {
                _logger.LogWarning("Fido2 attestation rejected: {Error}", result.ErrorMessage);
                return ProblemBadRequest("attestation");
            }

            var attested = result.Result;
            var transports = ExtractTransports(req.AttestationResponse);

            var entity = new WebAuthnCredential
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                CredentialId = attested.CredentialId,
                PublicKeyCose = attested.PublicKey,
                SignCount = attested.Counter,
                AaGuid = attested.Aaguid == Guid.Empty ? (Guid?)null : attested.Aaguid,
                Transports = transports,
                Nickname = string.IsNullOrWhiteSpace(req.Nickname) ? null : req.Nickname.Trim(),
                WrappedKeyCiphertext = wrapCt,
                WrappedKeyIv = wrapIv,
                WrappedKeyAuthTag = wrapTag,
                WrapMethod = req.WrappedKey.WrapMethod,
                CreatedUtc = DateTime.UtcNow,
            };
            _db.WebAuthnCredentials.Add(entity);
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            _logger.LogInformation("Passkey registered for {UserId} ({Method})", user.Id, req.WrappedKey.WrapMethod);
            return Ok(new { id = entity.Id });
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.register.finish", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Registration failed");
        }
    }

    // GET /api/webauthn/credentials
    //
    // Returns display metadata only — never the wrapped blob. The browser receives the
    // wrap from /assert/finish after a server-validated assertion, ensuring an attacker
    // who steals a session cookie can't lift the wrapped material directly.
    [HttpGet("credentials")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null) return SetupNotComplete();

            var rows = await _db.WebAuthnCredentials
                .Where(c => c.UserId == user.Id)
                .OrderByDescending(c => c.CreatedUtc)
                .Select(c => new WebAuthnCredentialSummary(
                    c.Id,
                    c.Nickname,
                    c.WrapMethod,
                    c.Transports,
                    c.CreatedUtc,
                    c.LastUsedUtc))
                .ToListAsync(ct).ConfigureAwait(false);

            return Ok(rows);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.credentials.list", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Could not list credentials");
        }
    }

    // DELETE /api/webauthn/credentials/{id}
    //
    // Hard-delete (REQ-026). 404 when the row doesn't exist OR doesn't belong to the
    // caller — same response either way to avoid telegraphing existence.
    [HttpDelete("credentials/{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();

            var row = await _db.WebAuthnCredentials
                .FirstOrDefaultAsync(c => c.Id == id && c.UserId == user.Id, ct)
                .ConfigureAwait(false);
            if (row is null) return NotFound();

            _db.WebAuthnCredentials.Remove(row);
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
            _logger.LogInformation("Passkey {CredId} revoked for {UserId}", row.Id, user.Id);
            return NoContent();
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.credentials.revoke", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Revoke failed");
        }
    }

    // POST /api/webauthn/assert/begin
    //
    // We return 409 (vault.access.denied) when the user has zero credentials — there is
    // no point starting a ceremony with an empty allowCredentials list, and the deadline
    // for "the wrong user is on this account" never arrives. Keeps the UI honest.
    [HttpPost("assert/begin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertBegin([FromBody] WebAuthnAssertBeginRequest? req, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null) return SetupNotComplete();

            var creds = await _db.WebAuthnCredentials
                .Where(c => c.UserId == user.Id)
                .Select(c => new { c.CredentialId, c.Transports, c.WrapMethod })
                .ToListAsync(ct).ConfigureAwait(false);

            if (creds.Count == 0) return AccessDenied("No registered passkey for this account.");

            // Optional preselect: filter to a specific credential id.
            byte[]? preselectId = null;
            if (!string.IsNullOrWhiteSpace(req?.CredentialId))
            {
                if (!TryDecodeBase64UrlOrStandard(req.CredentialId, out preselectId))
                    return ProblemBadRequest("credentialId");
                creds = creds.Where(c => c.CredentialId.AsSpan().SequenceEqual(preselectId.AsSpan())).ToList();
                if (creds.Count == 0) return NotFound();
            }

            var challenge = await _challenges.IssueAsync(user.Id, "assert", ct).ConfigureAwait(false);

            // Per-credential extension shape: we drop in largeBlob OR prf based on what
            // the user enrolled with. Fido2-Net-Lib doesn't model these so we hand-build.
            // When the user has multiple credentials with mixed wrap methods, we union the
            // extension request — both methods' extensions go up to the browser, and the
            // authenticator picks whichever matches.
            var anyLargeBlob = creds.Any(c => c.WrapMethod == "largeBlob");
            var anyPrf = creds.Any(c => c.WrapMethod == "prf");

            var extensions = new JsonObject();
            if (anyLargeBlob)
            {
                extensions["largeBlob"] = new JsonObject { ["read"] = true };
            }
            if (anyPrf)
            {
                extensions["prf"] = new JsonObject
                {
                    ["eval"] = new JsonObject
                    {
                        ["first"] = Base64Url.Encode(PrfInputV1),
                    },
                };
            }

            var options = new JsonObject
            {
                ["challenge"] = Base64Url.Encode(challenge),
                ["rpId"] = _fidoConfig.RpId,
                ["timeout"] = 60_000,
                ["userVerification"] = "preferred",
                ["allowCredentials"] = BuildAllowList(creds.Select(c => (c.CredentialId, c.Transports))),
                ["extensions"] = extensions,
            };

            return Ok(options);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.assert.begin", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Could not start assertion");
        }
    }

    // POST /api/webauthn/assert/finish
    //
    // Validates the assertion via Fido2.MakeAssertionAsync. On success: bump SignCount +
    // LastUsedUtc and return the wrapped-key envelope for the credential that authenticated.
    [HttpPost("assert/finish")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssertFinish([FromBody] WebAuthnAssertFinishRequest req, CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Unauthorized();
            if (user.MasterPasswordVerifierBlob is null) return SetupNotComplete();

            if (req?.AssertionResponse is null) return ProblemBadRequest("body");

            AuthenticatorAssertionRawResponse? raw;
            try
            {
                raw = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(
                    req.AssertionResponse.ToJsonString(),
                    JsonSerializerOptions.Web);
            }
            catch (JsonException)
            {
                return ProblemBadRequest("assertionResponse");
            }
            if (raw is null || raw.RawId is null || raw.RawId.Length == 0)
                return ProblemBadRequest("assertionResponse");

            var row = await _db.WebAuthnCredentials
                .FirstOrDefaultAsync(c => c.UserId == user.Id && c.CredentialId == raw.RawId, ct)
                .ConfigureAwait(false);
            if (row is null) return NotFound();

            var challenge = ExtractChallenge(raw.Response?.ClientDataJson);
            if (challenge is null || !await _challenges.ConsumeAsync(user.Id, challenge, "assert", ct).ConfigureAwait(false))
                return ProblemBadRequest("challenge");

            var origOptions = BuildLibraryAssertionOptions(challenge, row.CredentialId);

            // Fido2 callback: confirm the userHandle (if present in the response) belongs
            // to the credential row we matched. With a single-user product and own-row
            // selection above, this is belt-and-braces.
            IsUserHandleOwnerOfCredentialIdAsync ownerCheck = (args, _) =>
            {
                if (args.UserHandle is null || args.UserHandle.Length == 0) return Task.FromResult(true);
                return Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(user.Id.ToByteArray().AsSpan()));
            };

            AssertionVerificationResult verify;
            try
            {
                verify = await _fido2.MakeAssertionAsync(
                    raw,
                    origOptions,
                    row.PublicKeyCose,
                    (uint)row.SignCount,
                    ownerCheck,
                    requestTokenBindingId: null,
                    cancellationToken: ct)
                    .ConfigureAwait(false);
            }
            catch (Fido2VerificationException vex)
            {
                await _errorLog.LogAsync("webauthn.assert.verify", vex.Message, vex, ct).ConfigureAwait(false);
                return ProblemBadRequest("assertion");
            }

            if (verify.Status != "ok")
            {
                _logger.LogWarning("Fido2 assertion rejected: {Error}", verify.ErrorMessage);
                return ProblemBadRequest("assertion");
            }

            // Sign-count handling. Some authenticators emit 0 forever; treat
            // (newCounter == 0 && stored == 0) as valid. Reject only when the new value
            // is strictly less than a non-zero stored value.
            var newCounter = (long)verify.Counter;
            if (row.SignCount > 0 && newCounter < row.SignCount)
            {
                _logger.LogWarning("Sign count regression on credential {CredId}: stored={Stored}, new={New}",
                    row.Id, row.SignCount, newCounter);
                await _errorLog.LogAsync("webauthn.assert.signcount",
                    $"Sign count regression on credential {row.Id}: stored={row.SignCount}, new={newCounter}",
                    cancellationToken: ct).ConfigureAwait(false);
                return ProblemBadRequest("assertion");
            }

            row.SignCount = newCounter;
            row.LastUsedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            _logger.LogInformation("Passkey unlock for {UserId} via credential {CredId}", user.Id, row.Id);

            var response = new WebAuthnAssertFinishResponse(
                CredentialId: Convert.ToBase64String(row.CredentialId),
                WrappedKey: new WebAuthnWrappedKey(
                    Ciphertext: Convert.ToBase64String(row.WrappedKeyCiphertext),
                    Iv: Convert.ToBase64String(row.WrappedKeyIv),
                    AuthTag: Convert.ToBase64String(row.WrappedKeyAuthTag),
                    WrapMethod: row.WrapMethod));
            return Ok(response);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("webauthn.assert.finish", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem("Assertion failed");
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

    private CredentialCreateOptions BuildLibraryCreateOptions(ApplicationUser user, byte[] challenge)
    {
        var fidoUser = new Fido2User
        {
            Id = user.Id.ToByteArray(),
            Name = user.Email ?? user.UserName ?? user.Id.ToString(),
            DisplayName = user.DisplayName ?? user.Email ?? "Dragon Vault user",
        };
        var selection = new AuthenticatorSelection
        {
            UserVerification = UserVerificationRequirement.Preferred,
            RequireResidentKey = false,
        };
        // Fido2's static Create initialiser pulls RP id/name from the configured Fido2.
        return CredentialCreateOptions.Create(
            new Fido2Configuration
            {
                ServerDomain = _fidoConfig.RpId,
                ServerName = _fidoConfig.RpName,
                Origins = new HashSet<string>(_fidoConfig.Origins, StringComparer.Ordinal),
            },
            challenge,
            fidoUser,
            selection,
            AttestationConveyancePreference.None,
            excludeCredentials: null,
            extensions: null);
    }

    private AssertionOptions BuildLibraryAssertionOptions(byte[] challenge, byte[] credentialId)
    {
        var allowed = new[]
        {
            new PublicKeyCredentialDescriptor(credentialId),
        };
        return AssertionOptions.Create(
            new Fido2Configuration
            {
                ServerDomain = _fidoConfig.RpId,
                ServerName = _fidoConfig.RpName,
                Origins = new HashSet<string>(_fidoConfig.Origins, StringComparer.Ordinal),
            },
            challenge,
            allowed,
            UserVerificationRequirement.Preferred,
            extensions: null);
    }

    // Pulls the challenge bytes out of the WebAuthn clientDataJSON. Format is documented
    // by the spec: `{"type":"webauthn.create"|"webauthn.get","challenge":"<base64url>",...}`.
    // We don't validate type/origin here — Fido2.MakeNewCredentialAsync /
    // MakeAssertionAsync do that. We only need the challenge bytes to round-trip with
    // our challenge store.
    private static byte[]? ExtractChallenge(byte[]? clientDataJson)
    {
        if (clientDataJson is null || clientDataJson.Length == 0) return null;
        try
        {
            using var doc = JsonDocument.Parse(clientDataJson);
            if (!doc.RootElement.TryGetProperty("challenge", out var ch)) return null;
            var s = ch.GetString();
            if (string.IsNullOrEmpty(s)) return null;
            return Base64Url.Decode(s);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // Pulls "transports" out of the attestation response if the browser supplied them
    // (it's a sibling of "response.attestationObject" — `getTransports()` output).
    private static string? ExtractTransports(JsonNode attestationResponse)
    {
        var transports = attestationResponse["response"]?["transports"];
        if (transports is JsonArray arr && arr.Count > 0)
        {
            var values = arr.OfType<JsonValue>()
                .Select(v => v.GetValue<string>())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray();
            if (values.Length > 0) return string.Join(",", values);
        }
        return null;
    }

    private static JsonArray BuildAllowList(IEnumerable<(byte[] CredentialId, string? Transports)> rows)
    {
        var arr = new JsonArray();
        foreach (var (credId, transports) in rows)
        {
            var entry = new JsonObject
            {
                ["type"] = "public-key",
                ["id"] = Base64Url.Encode(credId),
            };
            if (!string.IsNullOrWhiteSpace(transports))
            {
                var t = new JsonArray();
                foreach (var part in transports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    t.Add(part);
                }
                entry["transports"] = t;
            }
            arr.Add(entry);
        }
        return arr;
    }

    // Length-validate base64 → byte[]; same shape as AccountApiController.TryDecodeBlob.
    private static bool TryDecodeBlob(string? value, int maxLength, bool allowEmpty, out byte[] bytes, bool exact = false)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(value)) return allowEmpty;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException) { return false; }
        if (bytes.Length == 0 && !allowEmpty) return false;
        if (exact ? bytes.Length != maxLength : bytes.Length > maxLength) return false;
        return true;
    }

    // Browser may send credential ids as base64url (WebAuthn norm) OR base64 (.NET norm)
    // depending on what wrote the value. Try both.
    private static bool TryDecodeBase64UrlOrStandard(string value, out byte[] bytes)
    {
        try { bytes = Base64Url.Decode(value); return true; }
        catch (FormatException) { /* fall through */ }
        try { bytes = Convert.FromBase64String(value); return true; }
        catch (FormatException) { bytes = []; return false; }
    }

    // ----- Problem Details factories (design §12) -----

    private IActionResult ProblemBadRequest(string field) =>
        Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "Validation failed",
            detail: $"Field '{field}' is missing or has the wrong shape.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.validation.error" });

    private IActionResult AccessDenied(string detail) =>
        Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Passkey unlock unavailable",
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = "vault.access.denied" });

    private IActionResult SetupNotComplete() =>
        Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Setup not complete",
            detail: "Configure a master password before using passkeys.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.setup.required" });

    private IActionResult InternalProblem(string title) =>
        Problem(
            statusCode: StatusCodes.Status500InternalServerError,
            title: title,
            extensions: new Dictionary<string, object?> { ["code"] = "vault.internal.error" });
}
