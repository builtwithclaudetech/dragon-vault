namespace PasswordManager.Web.Auth;

// REQ-004: forces Request.Scheme = "https" unconditionally before authentication runs.
//
// Why not UseForwardedHeaders? In-process IIS hosting has no real reverse proxy in front
// of Kestrel for this site, so X-Forwarded-Proto would be attacker-controllable — anyone
// could send X-Forwarded-Proto: http and silently strip the Secure flag from cookies.
// The a prior project postmortem traced multiple "Correlation failed" failures to exactly this
// path. Dragon Vault is HTTPS-only on port 8443; a constant assignment is correct AND safe.
internal static class HttpsSchemeMiddlewareExtensions
{
    public static IApplicationBuilder UseHttpsSchemeOverride(this IApplicationBuilder app) =>
        app.Use(static (ctx, next) =>
        {
            ctx.Request.Scheme = "https";
            return next();
        });
}
