using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using PasswordManager.Core.Domain;
using PasswordManager.Tests.Integration.TestAuth;

namespace PasswordManager.Tests.Integration;

// Phase E coverage for the /Vault/Entries view stub. Phase F replaces the stub markup
// with the real entries grid; the routing + auth shape we assert here is the part
// that's load-bearing forever:
//   - Anonymous → redirected to /Account/Login (cookie challenge).
//   - Authenticated, master-password setup not complete → 302 to /Account/Setup.
//   - Authenticated, setup complete → 200 with the lock-now button + session-lock
//     module bootstrap.
//
// The client-side lock policy itself (idle timer, BroadcastChannel, key-state
// redirect-to-Unlock) is JS-only — the server can't observe key state because it
// doesn't have one. Verifying the rendered markup here is enough to prove the JS
// hook points are present and stable.
public sealed class VaultEntriesViewTests : IClassFixture<DragonVaultWebApplicationFactory>
{
    private readonly DragonVaultWebApplicationFactory _factory;

    public VaultEntriesViewTests(DragonVaultWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private HttpClient CreateNonRedirectingClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

    private async Task<(HttpClient client, ApplicationUser user)> CreateAuthenticatedClientAsync(
        bool setupComplete,
        bool allowRedirects = true)
    {
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = $"phil-{Guid.NewGuid():N}@example.com",
            Email = $"phil-{Guid.NewGuid():N}@example.com",
            EmailConfirmed = true,
            KdfSalt = new byte[16],
            RecoverySalt = new byte[16],
        };
        Array.Fill<byte>(user.KdfSalt, 0xAA);
        Array.Fill<byte>(user.RecoverySalt, 0xBB);
        if (setupComplete)
        {
            user.VerifierCiphertext = new byte[16];
            user.VerifierIv = new byte[12];
            user.VerifierAuthTag = new byte[16];
            user.RecoveryWrappedKey = new byte[32];
            user.RecoveryWrapIv = new byte[12];
            user.RecoveryWrapAuthTag = new byte[16];
            user.MasterPasswordVerifierBlob = new byte[16];
        }
        var create = await userManager.CreateAsync(user);
        create.Succeeded.Should().BeTrue();

        var client = allowRedirects
            ? _factory.CreateClient()
            : CreateNonRedirectingClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.Id.ToString());
        return (client, user);
    }

    [Fact]
    public async Task Entries_Anonymous_RedirectsToLogin()
    {
        // Phase B already covers this for /Vault/Unlock; we re-verify for /Vault/Entries
        // because Phase E is the first phase to add it as a protected route.
        using var client = CreateNonRedirectingClient();

        var response = await client.GetAsync(new Uri("/Vault/Entries", UriKind.Relative));

        response.StatusCode.Should().Be(HttpStatusCode.Found);
        var location = response.Headers.Location;
        location.Should().NotBeNull();
        var pathAndQuery = location!.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
        pathAndQuery.Should().StartWith("/Account/Login");
        pathAndQuery.Should().Contain("ReturnUrl");
    }

    [Fact]
    public async Task Entries_AuthenticatedButSetupIncomplete_RedirectsToSetup()
    {
        var (client, _) = await CreateAuthenticatedClientAsync(setupComplete: false, allowRedirects: false);
        using (client)
        {
            var response = await client.GetAsync(new Uri("/Vault/Entries", UriKind.Relative));

            response.StatusCode.Should().Be(HttpStatusCode.Found);
            var location = response.Headers.Location;
            location.Should().NotBeNull();
            var pathAndQuery = location!.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
            pathAndQuery.Should().Be("/Account/Setup");
        }
    }

    [Fact]
    public async Task Entries_AuthenticatedAndSetupComplete_Returns200_WithLockButton()
    {
        var (client, user) = await CreateAuthenticatedClientAsync(setupComplete: true);
        using (client)
        {
            var response = await client.GetAsync(new Uri("/Vault/Entries", UriKind.Relative));

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await response.Content.ReadAsStringAsync();

            // REQ-019 hook point: the explicit "Lock now" button must be present so the
            // session-lock module can wire it. We don't assert the button text (Phase G
            // UX may rename it) — only the stable id.
            body.Should().Contain("id=\"lock-now\"");

            // REQ-018/REQ-081 hook point: the page must import session-lock.js. Without
            // this the idle timer + BroadcastChannel never arm.
            body.Should().Contain("/js/session-lock.js");
            body.Should().Contain("initSessionManagement");

            // REQ-020 hook point: the page must check key state on first paint and
            // bounce to /Vault/Unlock if the in-memory key is missing (hard reload).
            body.Should().Contain("/Vault/Unlock");

            // The user-id is plumbed for AAD bindings in Phase F; verify it's stamped.
            body.Should().Contain($"data-user-id=\"{user.Id}\"");
        }
    }

    [Fact]
    public async Task Unlock_AuthenticatedAndSetupComplete_Returns200_WithSessionLockBootstrap()
    {
        // Phase E also wires session-lock onto the unlock page itself (with
        // skipRedirectOnLock=true) so cross-tab lock messages reach a tab that's
        // sitting on /Vault/Unlock. Verify the import is there.
        var (client, _) = await CreateAuthenticatedClientAsync(setupComplete: true);
        using (client)
        {
            var response = await client.GetAsync(new Uri("/Vault/Unlock", UriKind.Relative));

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await response.Content.ReadAsStringAsync();
            body.Should().Contain("/js/session-lock.js");
            body.Should().Contain("skipRedirectOnLock");
        }
    }
}
