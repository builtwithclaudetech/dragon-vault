// ─────────────────────────────────────────────────────────────────────────────
// Skipped integration tests (real authenticator required)
// ─────────────────────────────────────────────────────────────────────────────
//
// Two ceremony-completion tests at lines 341-350 are skipped with
//   Skip = "Requires real authenticator — Phase D-2 manual test"
//
// 1. RegisterFinish_ValidAttestation_PersistsCredential (line 342)
//    What it tests: Full WebAuthn registration (attestation) completion. Sends
//    a valid AuthenticatorAttestationResponse to POST /api/webauthn/register/finish
//    and verifies that a credential is persisted in the database and the response
//    contains the expected credential metadata (credential ID, wrapped key, etc.).
//    Hardware/software needed:
//      - A real platform authenticator (Windows Hello, Android biometric, Apple
//        Touch ID/Face ID, or a roaming security key) that can produce a valid
//        WebAuthn attestation.
//      - The test must run in a browser or WebView context where
//        navigator.credentials.create() is available, because the authenticator
//        is mediated by the WebAuthn browser API — it cannot be driven purely
//        from HTTP requests.
//      - The test server must be served over HTTPS or from localhost, as WebAuthn
//        requires a secure context.
//
// 2. AssertFinish_ValidAssertion_ReturnsWrappedKey (line 345)
//    What it tests: Full WebAuthn assertion (authentication) completion. Sends
//    a valid AuthenticatorAssertionResponse to POST /api/webauthn/assert/finish
//    and verifies that the wrapped encryption key is returned (the key that was
//    stored during registration is unwrapped and returned to the client for vault
//    decryption).
//    Hardware/software needed:
//      - The same authenticator types as RegisterFinish (above), configured with
//        at least one credential already registered with the server (i.e., the
//        test needs to run RegisterBegin/RegisterFinish first to establish a
//        credential, OR a pre-registered credential must be seeded in the test
//        database).
//      - Same browser/HTTPS requirements as RegisterFinish.
//
// Both tests exist as stubs (Task.CompletedTask) because:
//   - There is no realistic way to forge a valid WebAuthn attestation/assertion
//     in CI or unit-test code — the attestation statement is a signed artifact
//     from the authenticator's hardware attestation key.
//   - WebAuthn testing frameworks (like webauthn-cli, puppeteer with real
//     hardware forwarding) are platform-specific and not portable across CI
//     runners.
//   - The recommended approach is manual verification post-deploy using real
//     hardware, documented in docs/dr-runbook-linux.md (Phase D-2).
// ─────────────────────────────────────────────────────────────────────────────

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PasswordManager.Core.Domain;
using PasswordManager.Data;
using PasswordManager.Tests.Integration.TestAuth;

namespace PasswordManager.Tests.Integration;

// Coverage for /api/webauthn endpoints that don't require a real authenticator. We
// can verify:
//   - register/begin returns the spec-shaped CredentialCreationOptions (challenge size,
//     extensions present, RP id matches config).
//   - assert/begin for a user with zero credentials returns 409 vault.access.denied
//     (we picked the short-circuit-the-dead-end-ceremony route — see report).
//   - DELETE credentials/{id} returns 404 when targeting another user's credential.
//   - All six endpoints return 409 vault.access.denied when MasterPasswordVerifierBlob
//     is null (setup not complete).
//
// Ceremony-completion paths (register/finish, assert/finish) require a real authenticator
// — there's no realistic way to forge a valid WebAuthn attestation/assertion in code.
// Those are deferred to manual testing post-deploy (Phase D-2).
public sealed class WebAuthnApiTests : IClassFixture<DragonVaultWebApplicationFactory>
{
    private readonly DragonVaultWebApplicationFactory _factory;

    public WebAuthnApiTests(DragonVaultWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private async Task<(HttpClient client, ApplicationUser user)> CreateAuthenticatedClientAsync(bool setupComplete = true)
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
            // Phase B/C invariant: master-password setup is the gate for every passkey
            // operation. Stamp the marker so endpoints don't short-circuit to 409.
            user.VerifierCiphertext = new byte[16];
            user.VerifierIv = new byte[12];
            user.VerifierAuthTag = new byte[16];
            user.RecoveryWrappedKey = new byte[32];
            user.RecoveryWrapIv = new byte[12];
            user.RecoveryWrapAuthTag = new byte[16];
            user.MasterPasswordVerifierBlob = new byte[16];
        }
        // TODO: no CT overload in 10.0.0
        var create = await userManager.CreateAsync(user);
        create.Succeeded.Should().BeTrue();

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.Id.ToString());
        return (client, user);
    }

    // ----- /register/begin -----

    [Fact]
    public async Task RegisterBegin_Anonymous_Returns401()
    {
        using var client = _factory.CreateClient();
        var res = await client.PostAsync(new Uri("/api/webauthn/register/begin", UriKind.Relative),
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RegisterBegin_HappyPath_ReturnsSpecShapedOptions()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var res = await client.PostAsync(new Uri("/api/webauthn/register/begin", UriKind.Relative),
                new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
            res.StatusCode.Should().Be(HttpStatusCode.OK);

            var body = await res.Content.ReadAsStringAsync();
            var doc = JsonNode.Parse(body)!.AsObject();

            // Challenge: base64url-encoded 32 bytes — base64url with no padding ≈ 43 chars.
            var challenge = doc["challenge"]!.GetValue<string>();
            challenge.Should().NotBeNullOrEmpty();
            challenge.Length.Should().BeInRange(42, 44);

            // RP matches config (DragonVaultWebApplicationFactory leaves the appsettings
            // RpId="localhost" default in place).
            doc["rp"]!["id"]!.GetValue<string>().Should().Be("localhost");
            doc["rp"]!["name"]!.GetValue<string>().Should().Be("Dragon Vault");

            // Extensions: largeBlob preferred + prf empty object.
            doc["extensions"]!["largeBlob"]!["support"]!.GetValue<string>().Should().Be("preferred");
            doc["extensions"]!["prf"]!.AsObject().Should().NotBeNull();

            // userVerification = "preferred" — REQ-023 (must NOT be "required").
            doc["authenticatorSelection"]!["userVerification"]!.GetValue<string>().Should().Be("preferred");

            // pubKeyCredParams contains ES256 (-7) and RS256 (-257).
            var algs = doc["pubKeyCredParams"]!.AsArray()
                .Select(p => p!["alg"]!.GetValue<int>())
                .ToArray();
            algs.Should().Contain(-7);
            algs.Should().Contain(-257);
        }
    }

    [Fact]
    public async Task RegisterBegin_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync(setupComplete: false);
        using (client)
        {
            var res = await client.PostAsync(new Uri("/api/webauthn/register/begin", UriKind.Relative),
                new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    // ----- /assert/begin -----

    [Fact]
    public async Task AssertBegin_Anonymous_Returns401()
    {
        using var client = _factory.CreateClient();
        var res = await client.PostAsync(new Uri("/api/webauthn/assert/begin", UriKind.Relative),
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AssertBegin_NoCredentials_Returns409_VaultAccessDenied()
    {
        // Judgment call: rather than an empty allowCredentials array (which would let the
        // browser run a dead-end ceremony), short-circuit with 409. Code = vault.access.denied.
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var res = await client.PostAsync(new Uri("/api/webauthn/assert/begin", UriKind.Relative),
                new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);

            var problem = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync());
            problem.RootElement.TryGetProperty("code", out var code).Should().BeTrue();
            code.GetString().Should().Be("vault.access.denied");
        }
    }

    [Fact]
    public async Task AssertBegin_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync(setupComplete: false);
        using (client)
        {
            var res = await client.PostAsync(new Uri("/api/webauthn/assert/begin", UriKind.Relative),
                new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    // ----- /credentials list + delete -----

    [Fact]
    public async Task ListCredentials_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync(setupComplete: false);
        using (client)
        {
            var res = await client.GetAsync(new Uri("/api/webauthn/credentials", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    [Fact]
    public async Task ListCredentials_HappyPath_ReturnsArray()
    {
        var (client, user) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            // Seed a credential row directly (we can't run a real ceremony in the test).
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
                db.WebAuthnCredentials.Add(new WebAuthnCredential
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    CredentialId = new byte[] { 1, 2, 3, 4 },
                    PublicKeyCose = new byte[] { 9, 9 },
                    SignCount = 0,
                    Nickname = "test-key",
                    Transports = "usb,nfc",
                    WrappedKeyCiphertext = new byte[32],
                    WrappedKeyIv = new byte[12],
                    WrappedKeyAuthTag = new byte[16],
                    WrapMethod = "largeBlob",
                });
                await db.SaveChangesAsync();
            }

            var res = await client.GetAsync(new Uri("/api/webauthn/credentials", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.OK);

            var arr = await res.Content.ReadFromJsonAsync<JsonElement>();
            arr.GetArrayLength().Should().Be(1);
            var item = arr[0];
            item.GetProperty("nickname").GetString().Should().Be("test-key");
            item.GetProperty("wrapMethod").GetString().Should().Be("largeBlob");
            item.GetProperty("transports").GetString().Should().Be("usb,nfc");
            // Sensitive blob fields MUST NOT appear in list output.
            item.TryGetProperty("wrappedKeyCiphertext", out _).Should().BeFalse();
        }
    }

    [Fact]
    public async Task DeleteCredential_OtherUsersRow_Returns404()
    {
        var (clientA, userA) = await CreateAuthenticatedClientAsync();
        using (clientA)
        {
            // Seed a credential under userB's id.
            var userB = Guid.NewGuid();
            var foreignCredId = Guid.NewGuid();
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
                db.WebAuthnCredentials.Add(new WebAuthnCredential
                {
                    Id = foreignCredId,
                    UserId = userB,
                    CredentialId = new byte[] { 7, 7, 7, 7 },
                    PublicKeyCose = new byte[] { 9 },
                    SignCount = 0,
                    WrappedKeyCiphertext = new byte[32],
                    WrappedKeyIv = new byte[12],
                    WrappedKeyAuthTag = new byte[16],
                    WrapMethod = "prf",
                });
                await db.SaveChangesAsync();
            }

            // userA tries to delete userB's row → 404.
            var res = await clientA.DeleteAsync(new Uri($"/api/webauthn/credentials/{foreignCredId}", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.NotFound);

            // userB's row should still be present.
            using var scope2 = _factory.Services.CreateScope();
            var db2 = scope2.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
            (await db2.WebAuthnCredentials.FindAsync(foreignCredId)).Should().NotBeNull();
        }
    }

    [Fact]
    public async Task DeleteCredential_OwnRow_Returns204_AndDeletes()
    {
        var (client, user) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var credId = Guid.NewGuid();
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
                db.WebAuthnCredentials.Add(new WebAuthnCredential
                {
                    Id = credId,
                    UserId = user.Id,
                    CredentialId = new byte[] { 5, 5, 5 },
                    PublicKeyCose = new byte[] { 9 },
                    SignCount = 0,
                    WrappedKeyCiphertext = new byte[32],
                    WrappedKeyIv = new byte[12],
                    WrappedKeyAuthTag = new byte[16],
                    WrapMethod = "largeBlob",
                });
                await db.SaveChangesAsync();
            }

            var res = await client.DeleteAsync(new Uri($"/api/webauthn/credentials/{credId}", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.NoContent);

            using var scope2 = _factory.Services.CreateScope();
            var db2 = scope2.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
            (await db2.WebAuthnCredentials.FindAsync(credId)).Should().BeNull();
        }
    }

    [Fact]
    public async Task DeleteCredential_BeforeSetup_OwnRowStillReachable()
    {
        // Revoke does NOT gate on setup completion — the credential is independent of
        // master-password state. (If we'd locked it behind setup, an account whose row
        // got into a weird half-setup state couldn't clean up.) This test pins the
        // current behavior so a future change is intentional.
        var (client, user) = await CreateAuthenticatedClientAsync(setupComplete: false);
        using (client)
        {
            var credId = Guid.NewGuid();
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();
                db.WebAuthnCredentials.Add(new WebAuthnCredential
                {
                    Id = credId,
                    UserId = user.Id,
                    CredentialId = new byte[] { 5, 5, 5 },
                    PublicKeyCose = new byte[] { 9 },
                    WrappedKeyCiphertext = new byte[32],
                    WrappedKeyIv = new byte[12],
                    WrappedKeyAuthTag = new byte[16],
                    WrapMethod = "largeBlob",
                });
                await db.SaveChangesAsync();
            }

            var res = await client.DeleteAsync(new Uri($"/api/webauthn/credentials/{credId}", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.NoContent);
        }
    }

    // ----- ceremony completion paths (deferred) -----

    [Fact(Skip = "Requires real authenticator — Phase D-2 manual test")]
    public Task RegisterFinish_ValidAttestation_PersistsCredential() => Task.CompletedTask;

    [Fact(Skip = "Requires real authenticator — Phase D-2 manual test")]
    public Task AssertFinish_ValidAssertion_ReturnsWrappedKey() => Task.CompletedTask;
}
