using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;
using PasswordManager.Web.Models;

namespace PasswordManager.Web.Controllers;

// JSON API for vault entries (REQ-027..032, REQ-071..072).
//
//   GET    /api/vault/entries            — list (UpdatedUtc DESC)
//   GET    /api/vault/entries/{id}       — single entry
//   POST   /api/vault/entries            — create (client supplies Id for AAD binding)
//   PUT    /api/vault/entries/{id}       — full replace (If-Match required → 412 on stale)
//   DELETE /api/vault/entries/{id}       — hard-delete (REQ-032)
//
// Server is a dumb relay for ciphertext: it never sees plaintext entry data, only the
// triple (ciphertext, iv, authTag) per encrypted blob. AAD construction lives entirely
// in the browser (wwwroot/js/vault.js) — it binds {entryId, label} so a server-side
// row-swap can't trick the browser into decrypting field A's bytes against field B's AAD.
//
// EntryFields cascade is intentionally Restrict (EntryFieldConfiguration) — service code
// removes child rows explicitly before the parent on PUT (full replace) and DELETE.
[ApiController]
[Authorize]
[Route("api/vault")]
public sealed class VaultApiController : ControllerBase
{
    private readonly DragonVaultDbContext _db;
    private readonly IErrorLogService _errorLog;

    public VaultApiController(DragonVaultDbContext db, IErrorLogService errorLog)
    {
        _db = db;
        _errorLog = errorLog;
    }

    private static readonly HashSet<string> AllowedFieldKinds = new(StringComparer.Ordinal)
    {
        "username", "password", "url", "notes", "totp_secret", "custom",
    };

    private Guid? CurrentUserId()
    {
        var claim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(claim, out var id) ? id : null;
    }

    // ----- GET list -----

    [HttpGet("entries")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        try
        {
            var userId = CurrentUserId();
            if (userId is null) return Forbid();

            var entries = await _db.VaultEntries
                .AsNoTracking()
                .Where(e => e.UserId == userId.Value)
                .OrderByDescending(e => e.UpdatedUtc)
                .Include(e => e.Fields)
                .ToListAsync(ct).ConfigureAwait(false);

            var response = entries.Select(MapToResponse).ToList();
            return Ok(response);
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("VaultApiController.List", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem();
        }
    }

    // ----- GET single -----

    [HttpGet("entries/{id:guid}", Name = nameof(GetEntry))]
    public async Task<IActionResult> GetEntry(Guid id, CancellationToken ct)
    {
        try
        {
            var userId = CurrentUserId();
            if (userId is null) return Forbid();

            var entry = await _db.VaultEntries
                .AsNoTracking()
                .Include(e => e.Fields)
                .FirstOrDefaultAsync(e => e.Id == id, ct)
                .ConfigureAwait(false);
            if (entry is null) return EntryNotFound();
            if (entry.UserId != userId.Value) return Forbid();

            return Ok(MapToResponse(entry));
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("VaultApiController.GetEntry", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem();
        }
    }

    // ----- POST create -----

    [HttpPost("entries")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([FromBody] CreateEntryRequest req, CancellationToken ct)
    {
        try
        {
            var userId = CurrentUserId();
            if (userId is null) return Forbid();

            if (req is null) return ValidationProblem("body");
            if (!ValidateCipher(req.Name, "name")) return ValidationProblem("name");
            if (req.Tags is not null && !ValidateCipher(req.Tags, "tags")) return ValidationProblem("tags");
            if (req.Fields is null) return ValidationProblem("fields");
            if (!ValidateFields(req.Fields, out var fieldsError)) return ValidationProblem(fieldsError);

            var duplicate = await _db.VaultEntries.AsNoTracking()
                .AnyAsync(e => e.Id == req.Id, ct).ConfigureAwait(false);
            if (duplicate) return ConflictProblem("Entry id already exists.", "vault.entry.conflict");

            var entry = new VaultEntry
            {
                Id = req.Id,
                UserId = userId.Value,
                NameCiphertext = FromB64(req.Name.Ciphertext),
                NameIv = FromB64(req.Name.Iv),
                NameAuthTag = FromB64(req.Name.AuthTag),
                TagsCiphertext = req.Tags is null ? null : FromB64(req.Tags.Ciphertext),
                TagsIv = req.Tags is null ? null : FromB64(req.Tags.Iv),
                TagsAuthTag = req.Tags is null ? null : FromB64(req.Tags.AuthTag),
            };
            foreach (var f in req.Fields)
            {
                entry.Fields.Add(BuildField(req.Id, f));
            }

            _db.VaultEntries.Add(entry);
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            // Round-trip read so RowVersion + audit timestamps are populated from the store.
            var saved = await _db.VaultEntries.AsNoTracking()
                .Include(e => e.Fields)
                .FirstAsync(e => e.Id == entry.Id, ct).ConfigureAwait(false);

            return CreatedAtAction(nameof(GetEntry), new { id = saved.Id }, MapToResponse(saved));
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("VaultApiController.Create", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem();
        }
    }

    // ----- PUT update (full replace) -----

    [HttpPut("entries/{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateEntryRequest req, CancellationToken ct)
    {
        try
        {
            var userId = CurrentUserId();
            if (userId is null) return Forbid();

            if (!Request.Headers.TryGetValue("If-Match", out var ifMatchValues) || ifMatchValues.Count == 0)
                return PreconditionRequired();
            var ifMatch = ifMatchValues[0];
            if (string.IsNullOrWhiteSpace(ifMatch)) return PreconditionRequired();

            byte[] originalRowVersion;
            try
            {
                originalRowVersion = Convert.FromBase64String(ifMatch);
            }
            catch (FormatException)
            {
                return ValidationProblem("If-Match");
            }

            if (req is null) return ValidationProblem("body");
            if (!ValidateCipher(req.Name, "name")) return ValidationProblem("name");
            if (req.Tags is not null && !ValidateCipher(req.Tags, "tags")) return ValidationProblem("tags");
            if (req.Fields is null) return ValidationProblem("fields");
            if (!ValidateFields(req.Fields, out var fieldsError)) return ValidationProblem(fieldsError);

            var entry = await _db.VaultEntries
                .Include(e => e.Fields)
                .FirstOrDefaultAsync(e => e.Id == id, ct)
                .ConfigureAwait(false);
            if (entry is null) return EntryNotFound();
            if (entry.UserId != userId.Value) return Forbid();

            // Pin EF's optimistic concurrency check to the client-supplied If-Match value.
            // SaveChangesAsync compares OriginalValue.RowVersion against the current row;
            // a mismatch raises DbUpdateConcurrencyException which we map to 412 below.
            _db.Entry(entry).Property(e => e.RowVersion).OriginalValue = originalRowVersion;

            entry.NameCiphertext = FromB64(req.Name.Ciphertext);
            entry.NameIv = FromB64(req.Name.Iv);
            entry.NameAuthTag = FromB64(req.Name.AuthTag);
            entry.TagsCiphertext = req.Tags is null ? null : FromB64(req.Tags.Ciphertext);
            entry.TagsIv = req.Tags is null ? null : FromB64(req.Tags.Iv);
            entry.TagsAuthTag = req.Tags is null ? null : FromB64(req.Tags.AuthTag);
            entry.UpdatedUtc = DateTime.UtcNow;

            // EntryFields FK is DeleteBehavior.Restrict — wipe the existing rows explicitly
            // and recreate from the request. Keeps the "full replace" semantics simple and
            // avoids merge-by-id complexity that no caller benefits from in v1.
            var existingFields = entry.Fields.ToList();
            foreach (var f in existingFields)
            {
                _db.EntryFields.Remove(f);
            }
            entry.Fields.Clear();
            foreach (var f in req.Fields)
            {
                entry.Fields.Add(BuildField(id, f));
            }

            // OQ-04: if the client sent a previous password, append it to the history.
            if (req.PreviousPassword is not null)
            {
                var history = DeserializeHistory(entry.PasswordHistoryJson);
                history.Add(new PasswordHistoryEntry(
                    req.PreviousPassword.Ciphertext,
                    req.PreviousPassword.Iv,
                    req.PreviousPassword.AuthTag,
                    DateTime.UtcNow.ToString("O")));
                if (history.Count > 5)
                    history = history.TakeLast(5).ToList();
                entry.PasswordHistoryJson = JsonSerializer.Serialize(history);
            }

            try
            {
                await _db.SaveChangesAsync(ct).ConfigureAwait(false);
            }
            catch (DbUpdateConcurrencyException)
            {
                return PreconditionFailed();
            }

            var saved = await _db.VaultEntries.AsNoTracking()
                .Include(e => e.Fields)
                .FirstAsync(e => e.Id == id, ct).ConfigureAwait(false);
            return Ok(MapToResponse(saved));
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("VaultApiController.Update", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem();
        }
    }

    // ----- DELETE -----

    [HttpDelete("entries/{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        try
        {
            var userId = CurrentUserId();
            if (userId is null) return Forbid();

            var entry = await _db.VaultEntries
                .Include(e => e.Fields)
                .FirstOrDefaultAsync(e => e.Id == id, ct)
                .ConfigureAwait(false);
            if (entry is null) return EntryNotFound();
            if (entry.UserId != userId.Value) return Forbid();

            // Restrict cascade — service code owns the child-then-parent ordering.
            foreach (var f in entry.Fields.ToList())
            {
                _db.EntryFields.Remove(f);
            }
            _db.VaultEntries.Remove(entry);
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            return NoContent();
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("VaultApiController.Delete", ex.Message, ex, ct).ConfigureAwait(false);
            return InternalProblem();
        }
    }

    // ----- mapping / validation helpers -----

    private static EntryResponse MapToResponse(VaultEntry e)
    {
        var name = new CipherBlobDto(
            Convert.ToBase64String(e.NameCiphertext),
            Convert.ToBase64String(e.NameIv),
            Convert.ToBase64String(e.NameAuthTag));
        CipherBlobDto? tags = null;
        if (e.TagsCiphertext is not null && e.TagsIv is not null && e.TagsAuthTag is not null)
        {
            tags = new CipherBlobDto(
                Convert.ToBase64String(e.TagsCiphertext),
                Convert.ToBase64String(e.TagsIv),
                Convert.ToBase64String(e.TagsAuthTag));
        }
        var fields = e.Fields
            .OrderBy(f => f.SortOrder)
            .Select(f => new EntryFieldResponse(
                f.Id,
                f.FieldKind,
                f.Key,          // OQ-05: plaintext key string, no longer a CipherBlobDto
                new CipherBlobDto(
                    Convert.ToBase64String(f.ValueCiphertext),
                    Convert.ToBase64String(f.ValueIv),
                    Convert.ToBase64String(f.ValueAuthTag)),
                f.SortOrder))
            .ToList();
        return new EntryResponse(
            e.Id,
            name,
            tags,
            fields,
            Convert.ToBase64String(e.RowVersion),
            e.CreatedUtc,
            e.UpdatedUtc);
    }

    private static EntryField BuildField(Guid entryId, EntryFieldRequest req)
    {
        var field = new EntryField
        {
            Id = Guid.NewGuid(),
            EntryId = entryId,
            FieldKind = req.FieldKind,
            ValueCiphertext = FromB64(req.Value.Ciphertext),
            ValueIv = FromB64(req.Value.Iv),
            ValueAuthTag = FromB64(req.Value.AuthTag),
            SortOrder = req.SortOrder,
        };
        // OQ-05: Key is now a plaintext string. The client sends it as a string, not a CipherBlobDto.
        if (req.Key is not null)
        {
            field.Key = req.Key;
        }
        return field;
    }

    private static bool ValidateCipher(CipherBlobDto blob, string _)
    {
        if (blob is null) return false;
        return IsNonEmptyBase64(blob.Ciphertext)
            && IsNonEmptyBase64(blob.Iv)
            && IsNonEmptyBase64(blob.AuthTag);
    }

    private static bool ValidateFields(IReadOnlyList<EntryFieldRequest> fields, out string error)
    {
        for (var i = 0; i < fields.Count; i++)
        {
            var f = fields[i];
            if (f is null) { error = $"fields[{i}]"; return false; }
            if (!AllowedFieldKinds.Contains(f.FieldKind)) { error = $"fields[{i}].fieldKind"; return false; }
            // OQ-05: Custom fields require a non-empty plaintext Key string (max 256 chars);
            // well-known kinds must NOT carry one (the kind itself names the field).
            if (f.FieldKind == "custom")
            {
                if (string.IsNullOrWhiteSpace(f.Key)) { error = $"fields[{i}].key"; return false; }
                if (f.Key.Length > 256) { error = $"fields[{i}].key"; return false; }
            }
            else if (f.Key is not null)
            {
                error = $"fields[{i}].key"; return false;
            }
            if (f.Value is null || !ValidateCipher(f.Value, "value")) { error = $"fields[{i}].value"; return false; }
        }
        error = string.Empty;
        return true;
    }

    private static bool IsNonEmptyBase64(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            var bytes = Convert.FromBase64String(value);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] FromB64(string value) => Convert.FromBase64String(value);

    // ----- Problem Details factories (design §12) -----

    private IActionResult ValidationProblem(string field) =>
        Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "Validation failed",
            detail: $"Field '{field}' is missing or has the wrong shape.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.validation.error" });

    private IActionResult ConflictProblem(string detail, string code) =>
        Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Conflict",
            detail: detail,
            extensions: new Dictionary<string, object?> { ["code"] = code });

    private IActionResult EntryNotFound() =>
        Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "Entry not found",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.entry.notfound" });

    private IActionResult PreconditionRequired() =>
        Problem(
            statusCode: StatusCodes.Status428PreconditionRequired,
            title: "If-Match header required",
            detail: "Send the entry's RowVersion in an If-Match header to update.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.precondition.required" });

    private IActionResult PreconditionFailed() =>
        Problem(
            statusCode: StatusCodes.Status412PreconditionFailed,
            title: "Entry was modified",
            detail: "The entry has changed since you last read it. Reload and retry.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.entry.conflict" });

    private IActionResult InternalProblem() =>
        Problem(
            statusCode: StatusCodes.Status500InternalServerError,
            title: "An error occurred.",
            extensions: new Dictionary<string, object?> { ["code"] = "vault.internal.error" });

    // ----- OQ-04 password history helpers -----

    private static List<PasswordHistoryEntry> DeserializeHistory(string? json)
    {
        if (string.IsNullOrEmpty(json))
            return [];
        try
        {
            return JsonSerializer.Deserialize<List<PasswordHistoryEntry>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

// Internal JSON-serializable record for password history entries stored in
// VaultEntry.PasswordHistoryJson. The fields (ciphertext, iv, tag) are base64
// strings from the client; the server is a dumb relay and never decrypts them.
internal sealed record PasswordHistoryEntry(
    string Ciphertext,
    string Iv,
    string Tag,
    string ChangedUtc);
