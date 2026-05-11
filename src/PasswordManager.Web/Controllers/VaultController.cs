using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Core.Domain;

namespace PasswordManager.Web.Controllers;

[Authorize]
public sealed class VaultController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public VaultController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpGet("/Vault/Unlock")]
    public async Task<IActionResult> Unlock(CancellationToken ct)
    {
        var user = await _userManager.GetUserAsync(User).ConfigureAwait(false);
        if (user is null) return Forbid();
        _ = ct;
        ViewData["UserId"] = user.Id.ToString();
        return View();
    }

    // Phase E stub. Phase F will land the entries grid + new-entry form. The current
    // shape exists so the lock policy has a real landing surface that:
    //   - is only reachable post-setup (otherwise → /Account/Setup)
    //   - hosts the "Lock now" button (REQ-019)
    //   - registers the idle / tab-hidden / cross-tab listeners via session-lock.js
    //
    // Note on session state: the auth cookie is sufficient on the server. We do NOT
    // gate this route on key-state because the key state is purely client-side
    // (see design §6 "Server-side, hitting any /api/vault/* while locked is the same
    // as while unlocked from the auth-cookie perspective"). The browser, on a fresh
    // navigation here without a key in memory, will redirect itself back to
    // /Vault/Unlock via the session-lock module's bootstrap check.
    [HttpGet("/Vault/Entries")]
    public async Task<IActionResult> Entries(CancellationToken ct)
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idClaim, out var id)) return Forbid();
        // UserManager.FindByIdAsync has no CT overload in 10.0.0; the action still
        // forwards ct so future EF-direct lookups can use it.
        _ = ct;
        var user = await _userManager.FindByIdAsync(id.ToString()).ConfigureAwait(false);
        if (user is null) return Forbid();
        if (user.MasterPasswordVerifierBlob is null)
        {
            return Redirect("/Account/Setup");
        }

        ViewData["UserId"] = user.Id.ToString();
        return View();
    }
}
