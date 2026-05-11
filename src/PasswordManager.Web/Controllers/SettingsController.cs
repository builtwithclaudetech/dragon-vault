using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Core.Domain;

namespace PasswordManager.Web.Controllers;

// Settings surface. Phase D adds the Passkeys page; future phases (lock policy,
// generator defaults, etc.) layer on here.
[Authorize]
public sealed class SettingsController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public SettingsController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    // GET /Settings/Passkeys
    //
    // Routes back to /Account/Setup if master-password setup hasn't completed yet —
    // there's no encryption key to wrap so no point landing on the passkey page.
    [HttpGet("/Settings/Passkeys")]
    public async Task<IActionResult> Passkeys(CancellationToken ct)
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idClaim, out var id)) return Forbid();
        // UserManager.FindByIdAsync has no CancellationToken overload in 10.0.0; the action
        // still accepts ct so future EF-direct lookups can forward it.
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
