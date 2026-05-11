using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;
using PasswordManager.Data.Services;
using PasswordManager.Web.Auth;
using PasswordManager.Web.Services;
using Serilog;

// Bootstrap logger (design §13.12). Captures startup failures before IErrorLogService is ready.
// REQ-059 (amended for Linux): writes to stdout (systemd journal) AND a rolling file sink at
// /var/opt/dragonvault/logs/ (Linux) or C:\inetpub\dragonvault\logs\ (Windows fallback).
var bootstrapLogPath = OperatingSystem.IsWindows()
    ? @"C:\inetpub\dragonvault\logs\bootstrap-.log"
    : "/var/opt/dragonvault/logs/bootstrap-.log";
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Warning()
    .WriteTo.Console()
    .WriteTo.File(bootstrapLogPath,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14)
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog();

    // REQ-074: persist DataProtection keys so AppPool recycles don't invalidate cookies
    // or break the Google correlation cookie path. SetApplicationName must match the
    // value Identity uses to derive cookie purposes — "dragon-vault" is the canonical
    // identifier for this app and MUST stay stable forever (changing it invalidates
    // every existing cookie).
    // Path adapts to OS: Windows uses C:\inetpub, Linux uses /var/opt/dragonvault/dpkeys.
    var dpKeysPath = OperatingSystem.IsWindows()
        ? @"C:\inetpub\dragonvault-dpkeys"
        : "/var/opt/dragonvault/dpkeys";
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(dpKeysPath))
        .SetApplicationName("dragon-vault");

    // Audit interceptor needs the current user; HttpContext-backed accessor lets the
    // Data assembly stay free of ASP.NET Core dependencies.
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<ICurrentUserAccessor, HttpContextCurrentUserAccessor>();
    builder.Services.AddScoped<AuditSaveChangesInterceptor>();

    builder.Services.AddDbContext<DragonVaultDbContext>((sp, options) =>
    {
        var cs = builder.Configuration.GetConnectionString("DragonVault")
                 ?? builder.Configuration.GetConnectionString("Default");
        options.UseSqlServer(cs);
        options.AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>());
    });

    builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>()
        .AddEntityFrameworkStores<DragonVaultDbContext>()
        .AddDefaultTokenProviders();

    // REQ-008: belt-and-braces enforcement that every cookie this app issues carries
    // the Secure flag. Identity's own cookies are configured for HTTPS-only via this
    // policy; the Google correlation cookie sets SecurePolicy on its own.
    builder.Services.Configure<CookiePolicyOptions>(o =>
    {
        o.Secure = CookieSecurePolicy.Always;
        o.MinimumSameSitePolicy = SameSiteMode.Lax;
    });

    // REQ-001..007, REQ-009: Google OAuth handler with correlation-cookie hardening,
    // PKCE off, and inline OnTicketReceived sign-in.
    builder.Services.AddDragonVaultGoogle(builder.Configuration);

    // Anti-forgery groundwork for Phase F (REQ-072). Header name matches the meta-tag
    // pattern documented in design §11; registration here is harmless until vault POSTs
    // arrive in Phase F and middleware is wired up.
    builder.Services.AddAntiforgery(o => o.HeaderName = "RequestVerificationToken");

    builder.Services.AddSingleton<IErrorLogService, ErrorLogService>();

    // REQ-077: background hosted service prunes expired WebAuthnChallenges hourly
    // and ErrorLog rows older than 90 days nightly. Resilient to transient DB failures.
    builder.Services.AddHostedService<PruningHostedService>();

    // REQ-021..026: WebAuthn passkey unlock. Registers Fido2-Net-Lib + the EF-backed
    // challenge store + the bound WebAuthn options. CSP / Permissions-Policy headers for
    // publickey-credentials-* are Phase L's responsibility.
    builder.Services.AddDragonVaultFido2(builder.Configuration);

    builder.Services.AddControllersWithViews();
    builder.Services.AddRazorPages();

    var app = builder.Build();

    // REQ-068: auto-migrate only outside Development; dev runs `dotnet ef database update` manually.
    if (!app.Environment.IsDevelopment())
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
        db.Database.Migrate();
    }

    // REQ-004: scheme middleware MUST run before UseAuthentication so cookie issuance
    // sees Request.Scheme = "https" and stamps cookies / OAuth state correctly.
    app.UseHttpsSchemeOverride();

    // REQ-070 belt-and-braces: security headers from the app side as a backup to nginx.
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "same-origin";
        ctx.Response.Headers["Permissions-Policy"] = "clipboard-write=(self), publickey-credentials-get=(self), publickey-credentials-create=(self)";
        if (!app.Environment.IsDevelopment())
        {
            ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }
        await next();
    });

    var staticFileOptions = new StaticFileOptions();
    var contentTypeProvider = new FileExtensionContentTypeProvider();
    contentTypeProvider.Mappings[".webmanifest"] = "application/manifest+json";
    staticFileOptions.ContentTypeProvider = contentTypeProvider;
    app.UseStaticFiles(staticFileOptions);

    app.UseRouting();

    // REQ-008: cookie policy filter runs before auth so it covers every Set-Cookie.
    app.UseCookiePolicy();

    app.UseAuthentication();
    app.UseAuthorization();

    // REQ-060: liveness/readiness probe gated on DB connectivity.
    app.MapGet("/healthz", async (DragonVaultDbContext db, CancellationToken ct) =>
    {
        try
        {
            var ok = await db.Database.CanConnectAsync(ct);
            return ok ? Results.Text("OK", "text/plain", null, 200) : Results.StatusCode(503);
        }
        catch (Exception ex)
        {
            app.Logger.LogWarning(ex, "healthz DB probe failed");
            return Results.StatusCode(503);
        }
    });

    app.MapGet("/", () => Results.Redirect("/Account/Login"));

    app.MapControllers();
    app.MapRazorPages();

    app.Run();
}
// Serilog bootstrap pattern: log+rethrow ensures startup failures land in the bootstrap file before the host swallows them.
catch (Exception ex)
{
    Log.Fatal(ex, "Dragon Vault host terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

// Marker for WebApplicationFactory<Program> in integration tests.
public partial class Program { }
