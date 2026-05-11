using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PasswordManager.Core.Domain;
using PasswordManager.Tests.Integration.TestAuth;
using PasswordManager.Web.Models;

namespace PasswordManager.Tests.Integration;

// Coverage for /api/account/{setup,kdf-info,recovery-info,rotate-master}.
//   - Anonymous → 401 (TestAuth handler returns NoResult; cookie scheme challenges).
//   - Authenticated requires structurally valid base64 / lengths.
//   - Setup writes MasterPasswordVerifierBlob (REQ-009 routing flag).
//   - Re-running setup is rejected (idempotency / replay guard).
public sealed class AccountApiTests : IClassFixture<DragonVaultWebApplicationFactory>
{
    private readonly DragonVaultWebApplicationFactory _factory;

    public AccountApiTests(DragonVaultWebApplicationFactory factory)
    {
        _factory = factory;
    }

    private async Task<(HttpClient client, ApplicationUser user)> CreateAuthenticatedClientAsync()
    {
        // Seed a user with the per-user salts already populated (mirrors what
        // GET /Account/Setup would have done). Skip the controller round-trip so the
        // tests stay focused on the JSON API surface.
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
        // TODO: no CT overload in 10.0.0
        var create = await userManager.CreateAsync(user);
        create.Succeeded.Should().BeTrue();

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.Id.ToString());
        return (client, user);
    }

    private static SetupRequest WellFormedSetupRequest()
    {
        // 16-byte verifier ciphertext (matches plaintext length from design §4.4),
        // 12-byte IV, 16-byte tag — the lengths the controller validates exactly.
        return new SetupRequest(
            VerifierCiphertext: B64Of(16),
            VerifierIv: B64Of(12),
            VerifierAuthTag: B64Of(16),
            RecoveryWrappedKey: B64Of(32),
            RecoveryWrappedKeyIv: B64Of(12),
            RecoveryWrappedKeyAuthTag: B64Of(16));
    }

    private static string B64Of(int byteCount)
    {
        var b = new byte[byteCount];
        for (var i = 0; i < byteCount; i++) b[i] = (byte)i;
        return Convert.ToBase64String(b);
    }

    [Fact]
    public async Task Setup_Anonymous_Returns401()
    {
        using var client = _factory.CreateClient();
        var res = await client.PostAsJsonAsync("/api/account/setup", WellFormedSetupRequest());
        // ASP.NET Core's default cookie challenge against an [ApiController] returns 401
        // because Authentication's challenge for cookie auth on a non-browser request
        // produces 401 (cookie redirect path is suppressed for API controllers).
        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Setup_Authenticated_HappyPath_PersistsVerifierBlob()
    {
        var (client, user) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var res = await client.PostAsJsonAsync("/api/account/setup", WellFormedSetupRequest());
            res.StatusCode.Should().Be(HttpStatusCode.NoContent);

            // Round-trip read: kdf-info should now succeed (requires verifier set).
            var kdf = await client.GetFromJsonAsync<KdfInfoResponse>("/api/account/kdf-info");
            kdf.Should().NotBeNull();
            kdf!.KdfIterations.Should().Be(3);
            kdf.KdfMemoryKb.Should().Be(65536);
            kdf.KdfParallelism.Should().Be(4);
            kdf.KdfOutputBytes.Should().Be(32);
            kdf.VerifierCiphertext.Should().Be(B64Of(16));
        }
    }

    [Fact]
    public async Task Setup_RunTwice_SecondCallReturns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var first = await client.PostAsJsonAsync("/api/account/setup", WellFormedSetupRequest());
            first.StatusCode.Should().Be(HttpStatusCode.NoContent);

            var second = await client.PostAsJsonAsync("/api/account/setup", WellFormedSetupRequest());
            second.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    [Theory]
    [InlineData("verifierIv", 11)]
    [InlineData("verifierIv", 13)]
    [InlineData("verifierAuthTag", 15)]
    [InlineData("verifierAuthTag", 17)]
    [InlineData("recoveryWrappedKeyIv", 8)]
    public async Task Setup_WrongLengthBlob_Returns400(string brokenField, int badLength)
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var ok = WellFormedSetupRequest();
            var wrong = B64Of(badLength);
            var bad = brokenField switch
            {
                "verifierIv" => ok with { VerifierIv = wrong },
                "verifierAuthTag" => ok with { VerifierAuthTag = wrong },
                "recoveryWrappedKeyIv" => ok with { RecoveryWrappedKeyIv = wrong },
                _ => throw new ArgumentOutOfRangeException(nameof(brokenField)),
            };
            var res = await client.PostAsJsonAsync("/api/account/setup", bad);
            res.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }

    [Fact]
    public async Task KdfInfo_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var res = await client.GetAsync(new Uri("/api/account/kdf-info", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    [Fact]
    public async Task RecoveryInfo_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var res = await client.GetAsync(new Uri("/api/account/recovery-info", UriKind.Relative));
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }

    [Fact]
    public async Task RotateMaster_AfterSetup_PersistsNewVerifier()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var setupRes = await client.PostAsJsonAsync("/api/account/setup", WellFormedSetupRequest());
            setupRes.StatusCode.Should().Be(HttpStatusCode.NoContent);

            // Different bytes for the rotated verifier so we can read them back.
            byte[] DifferentBytes(int len)
            {
                var b = new byte[len];
                for (var i = 0; i < len; i++) b[i] = (byte)(0xF0 | i);
                return b;
            }
            var rotate = new RotateMasterRequest(
                KdfSalt: Convert.ToBase64String(DifferentBytes(16)),
                VerifierCiphertext: Convert.ToBase64String(DifferentBytes(16)),
                VerifierIv: Convert.ToBase64String(DifferentBytes(12)),
                VerifierAuthTag: Convert.ToBase64String(DifferentBytes(16)),
                RecoveryWrappedKey: Convert.ToBase64String(DifferentBytes(32)),
                RecoveryWrappedKeyIv: Convert.ToBase64String(DifferentBytes(12)),
                RecoveryWrappedKeyAuthTag: Convert.ToBase64String(DifferentBytes(16)));
            var res = await client.PostAsJsonAsync("/api/account/rotate-master", rotate);
            res.StatusCode.Should().Be(HttpStatusCode.NoContent);

            var kdf = await client.GetFromJsonAsync<KdfInfoResponse>("/api/account/kdf-info");
            kdf.Should().NotBeNull();
            kdf!.VerifierCiphertext.Should().Be(rotate.VerifierCiphertext);
        }
    }

    [Fact]
    public async Task RotateMaster_BeforeSetup_Returns409()
    {
        var (client, _) = await CreateAuthenticatedClientAsync();
        using (client)
        {
            var rotate = new RotateMasterRequest(
                KdfSalt: B64Of(16),
                VerifierCiphertext: B64Of(16),
                VerifierIv: B64Of(12),
                VerifierAuthTag: B64Of(16),
                RecoveryWrappedKey: B64Of(32),
                RecoveryWrappedKeyIv: B64Of(12),
                RecoveryWrappedKeyAuthTag: B64Of(16));
            var res = await client.PostAsJsonAsync("/api/account/rotate-master", rotate);
            res.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }
}
