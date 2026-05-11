using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;
using PasswordManager.Web.Crypto;

namespace PasswordManager.Web.Controllers;

// Auth surface. Phase B owns Login / ExternalLogin / Logout; Phase C adds Setup material
// (server-side recovery-code + salt generation) and the Recover view.
public sealed class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly DragonVaultDbContext _db;
    private readonly IErrorLogService _errorLog;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        DragonVaultDbContext db,
        IErrorLogService errorLog,
        ILogger<AccountController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
        _errorLog = errorLog;
        _logger = logger;
    }

    [HttpGet("/Account/Login")]
    [AllowAnonymous]
    public IActionResult Login([FromQuery] string? error)
    {
        ViewData["Error"] = error switch
        {
            "auth_failed" => "auth_failed",
            "not_allowed" => "not_allowed",
            _ => null,
        };
        return View();
    }

    [HttpGet("/Account/ExternalLogin")]
    [AllowAnonymous]
    public IActionResult ExternalLogin()
    {
        const string provider = GoogleDefaults.AuthenticationScheme;
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback)) ?? "/";
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet("/Account/ExternalLoginCallback")]
    [AllowAnonymous]
    public IActionResult ExternalLoginCallback() =>
        RedirectToAction(nameof(Login), new { error = "auth_failed" });

    // GET /Account/Setup
    //
    // Phase C contract:
    //   - Setup is a single-use page. If the user already configured their master
    //     password, redirect them to Unlock (REQ-009 invariant).
    //   - On every render we generate fresh KdfSalt, RecoverySalt, and a one-time
    //     recovery code. The salts get persisted immediately so the POST can validate
    //     against them; the recovery code is shown ONCE in the page payload and never
    //     persisted on the server.
    //   - Reloading the page rotates all three values — accepted UX cost. The user
    //     hasn't completed setup yet so nothing depends on the old values.
    [HttpGet("/Account/Setup")]
    [Authorize]
    public async Task<IActionResult> Setup(CancellationToken ct)
    {
        try
        {
            var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
            if (user is null) return Forbid();

            if (user.MasterPasswordVerifierBlob is { Length: > 0 })
            {
                return Redirect("/Vault/Unlock");
            }

            // Generate fresh material. Salts are persisted; the recovery code is shown
            // once in the response body and dropped from server memory after this call.
            user.KdfSalt = SetupMaterialFactory.NewKdfSalt();
            user.RecoverySalt = SetupMaterialFactory.NewRecoverySalt();
            // Initialize Argon2id parameters to design §4.1 defaults if unset.
            if (user.KdfIterations <= 0) user.KdfIterations = 3;
            if (user.KdfMemoryKb <= 0) user.KdfMemoryKb = 65536;
            if (user.KdfParallelism <= 0) user.KdfParallelism = 4;
            if (user.KdfOutputBytes <= 0) user.KdfOutputBytes = 32;

            await _db.SaveChangesAsync(ct).ConfigureAwait(false);

            var recoveryCode = SetupMaterialFactory.NewRecoveryCode();

            ViewData["KdfSalt"] = Convert.ToBase64String(user.KdfSalt);
            ViewData["RecoverySalt"] = Convert.ToBase64String(user.RecoverySalt);
            ViewData["KdfIterations"] = user.KdfIterations;
            ViewData["KdfMemoryKb"] = user.KdfMemoryKb;
            ViewData["KdfParallelism"] = user.KdfParallelism;
            ViewData["KdfOutputBytes"] = user.KdfOutputBytes;
            ViewData["RecoveryCode"] = recoveryCode;
            ViewData["UserId"] = user.Id.ToString();
            return View();
        }
        catch (Exception ex)
        {
            await _errorLog.LogAsync("account.setup.get", ex.Message, ex, ct).ConfigureAwait(false);
            return RedirectToAction(nameof(Login), new { error = "auth_failed" });
        }
    }

    // GET /Account/Recover
    //
    // Returns the recovery page; the JS module fetches /api/account/recovery-info itself.
    // Authorize is required — only a signed-in user (via Google) can access recovery.
    [HttpGet("/Account/Recover")]
    [Authorize]
    public async Task<IActionResult> Recover(CancellationToken ct)
    {
        var user = await ResolveCurrentUserAsync().ConfigureAwait(false);
        if (user is null) return Forbid();
        if (user.MasterPasswordVerifierBlob is null)
        {
            return Redirect("/Account/Setup");
        }
        ViewData["UserId"] = user.Id.ToString();
        return View();
    }

    [HttpPost("/Account/Logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync().ConfigureAwait(false);
        return RedirectToAction(nameof(Login));
    }

    private async Task<ApplicationUser?> ResolveCurrentUserAsync()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(idClaim, out var id)) return null;
        // TODO: no CT overload in 10.0.0
        return await _userManager.FindByIdAsync(id.ToString()).ConfigureAwait(false);
    }
}
