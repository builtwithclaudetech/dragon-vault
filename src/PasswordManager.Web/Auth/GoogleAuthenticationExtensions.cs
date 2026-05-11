using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Web.Auth;

internal static class GoogleAuthenticationExtensions
{
    // Registers the Google handler on top of the cookie scheme that AddIdentity already
    // configured. The cookie defaults stay as Identity set them — we only layer Google
    // as the challenge scheme so external sign-in lands on the Identity application cookie
    // after OnTicketReceived.SignInAsync.
    public static IServiceCollection AddDragonVaultGoogle(this IServiceCollection services, IConfiguration configuration)
    {
        var googleOptions = configuration.GetSection(GoogleAuthOptions.SectionName).Get<GoogleAuthOptions>()
            ?? new GoogleAuthOptions();

        services.AddSingleton(googleOptions);

        // The AddAuthentication().AddGoogle(...) chain runs for side-effects (registering the
        // Google handler against the shared AuthenticationBuilder). We return IServiceCollection
        // so callers compose normally with the rest of Program.cs registration.
        services.AddAuthentication()
            .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
            {
                options.ClientId = googleOptions.ClientId;
                options.ClientSecret = googleOptions.ClientSecret;
                options.CallbackPath = "/signin-google";

                // REQ-003 (ADR-006): Google's "Web Application" OAuth client returns
                // invalid_client when PKCE is combined with client_secret. The a prior project
                // session that nailed this: enabling PKCE made the flow fail because
                // Google ignores the verifier and the correlation cookie path subtly
                // breaks behind IIS. Confidential server-side client makes PKCE optional.
                options.UsePkce = false;

                // REQ-007: correlation cookie hardening. IsEssential=true so the cookie
                // policy doesn't strip it on first visit before consent; SameSite=Lax
                // because the OAuth redirect is a top-level navigation back from Google;
                // SecurePolicy=Always because the site is HTTPS-only.
                options.CorrelationCookie.IsEssential = true;
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;

                options.SaveTokens = false;

                // REQ-006: any failure during the Google round-trip lands the user back on
                // /Account/Login with a friendly banner; the raw exception goes to logs only.
                options.Events.OnRemoteFailure = async ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                    var errorLog = ctx.HttpContext.RequestServices.GetRequiredService<IErrorLogService>();

                    logger.LogWarning(ctx.Failure, "Google remote failure: {Message}", ctx.Failure?.Message);
                    await errorLog.LogAsync(
                        "auth.google",
                        $"Remote failure during Google OAuth round-trip: {ctx.Failure?.Message}",
                        cancellationToken: ctx.HttpContext.RequestAborted)
                        .ConfigureAwait(false);

                    ctx.Response.Redirect("/Account/Login?error=auth_failed");
                    ctx.HandleResponse();
                };

                // REQ-005: do upsert + SignInAsync + redirect inline. No GoogleCallback
                // action — that's the second-cookie-hop bug from the a prior project postmortem.
                options.Events.OnTicketReceived = HandleGoogleTicketAsync;
            });

        return services;
    }

    private static async Task HandleGoogleTicketAsync(TicketReceivedContext ctx)
    {
        var services = ctx.HttpContext.RequestServices;
        var allowlist = services.GetRequiredService<GoogleAuthOptions>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var signInManager = services.GetRequiredService<SignInManager<ApplicationUser>>();
        var logger = services.GetRequiredService<ILogger<Program>>();
        var errorLog = services.GetRequiredService<IErrorLogService>();
        var ct = ctx.HttpContext.RequestAborted;

        var email = ctx.Principal?.FindFirstValue(ClaimTypes.Email);
        var googleSubject = ctx.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(email))
        {
            logger.LogWarning("Google ticket arrived without an email claim; rejecting");
            await errorLog.LogAsync(
                "auth.google",
                "Google ticket arrived without an email claim; rejecting",
                cancellationToken: ct).ConfigureAwait(false);
            ctx.Response.Redirect("/Account/Login?error=auth_failed");
            ctx.HandleResponse();
            return;
        }

        // REQ-002: hardcoded allowlist (one entry — the maintainer). Anyone else gets bounced.
        var isAllowed = allowlist.AllowedEmails
            .Any(e => string.Equals(e, email, StringComparison.OrdinalIgnoreCase));
        if (!isAllowed)
        {
            logger.LogWarning("Rejecting Google sign-in for non-allowlisted email {Email}", email);
            await errorLog.LogAsync(
                "auth.google",
                $"Rejecting Google sign-in for non-allowlisted email {email}",
                cancellationToken: ct).ConfigureAwait(false);
            ctx.Response.Redirect("/Account/Login?error=not_allowed");
            ctx.HandleResponse();
            return;
        }

        // TODO: no CT overload in 10.0.0
        var user = await userManager.FindByEmailAsync(email).ConfigureAwait(false);
        if (user is null)
        {
            user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                GoogleSubject = googleSubject,
                DisplayName = ctx.Principal?.FindFirstValue(ClaimTypes.Name),
            };

            // TODO: no CT overload in 10.0.0
            var create = await userManager.CreateAsync(user).ConfigureAwait(false);
            if (!create.Succeeded)
            {
                var errorCodes = string.Join(';', create.Errors.Select(e => e.Code));
                logger.LogError("Failed to create user {Email}: {Errors}", email, errorCodes);
                await errorLog.LogAsync(
                    "auth.google",
                    $"Failed to create user {email}: {errorCodes}",
                    cancellationToken: ct).ConfigureAwait(false);
                ctx.Response.Redirect("/Account/Login?error=auth_failed");
                ctx.HandleResponse();
                return;
            }
        }
        else if (string.IsNullOrEmpty(user.GoogleSubject) && !string.IsNullOrEmpty(googleSubject))
        {
            user.GoogleSubject = googleSubject;
            // TODO: no CT overload in 10.0.0
            await userManager.UpdateAsync(user).ConfigureAwait(false);
        }

        // SignInManager.SignInAsync issues the Identity application cookie. We deliberately
        // bypass the external-login cookie hop here — REQ-005 mandates inline sign-in.
        // TODO: no CT overload in 10.0.0
        await signInManager.SignInAsync(user, isPersistent: true).ConfigureAwait(false);

        // REQ-009: the master-password verifier blob lives on ApplicationUser. Phase C
        // writes it during /Account/Setup. Until that lands, every authenticated user
        // routes to Setup; once Phase C ships, returning users land on Unlock.
        var redirect = user.MasterPasswordVerifierBlob is null
            ? "/Account/Setup"
            : "/Vault/Unlock";

        ctx.Response.Redirect(redirect);
        ctx.HandleResponse();
    }
}
