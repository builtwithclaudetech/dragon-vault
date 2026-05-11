using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PasswordManager.Data;
using PasswordManager.Tests.Integration.TestAuth;

namespace PasswordManager.Tests.Integration;

// Test factory that swaps the SQL Server DbContext for an in-memory provider and steers
// DataProtection at a per-instance temp directory so the suite never touches the production
// IIS log paths or `C:\inetpub`.
//
// The audit interceptor is preserved (we keep the Web project's full DI graph) so endpoint
// tests cover the production wiring rather than a stripped-down harness.
public sealed class DragonVaultWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = $"dragonvault-tests-{Guid.NewGuid()}";
    private readonly string _dpKeysPath = Path.Combine(Path.GetTempPath(),
        $"dragonvault-tests-dpkeys-{Guid.NewGuid()}");

    protected override IHost CreateHost(IHostBuilder builder)
    {
        // Pre-create the data-protection key directory before the host starts so the
        // PersistKeysToFileSystem call in Program.cs targets a real path even when tests
        // never actually exercise key-protection. We layer our own PersistKeysToFileSystem
        // override below; this still helps if the production registration races first.
        Directory.CreateDirectory(_dpKeysPath);
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(Environments.Development);

        // Google handler validates ClientId/ClientSecret are non-empty (PostConfigure throws
        // on the first request that walks the auth scheme list — which is every request,
        // because Identity registers cookie auth as the default). Supply harmless test values
        // so the host can boot. UseSetting writes into the builder's configuration store
        // before Program.cs reads it, unlike ConfigureAppConfiguration which is sequenced
        // after the WebApplicationBuilder has already snapshotted GoogleAuthOptions.
        builder.UseSetting("Authentication:Google:ClientId", "test-client-id.apps.googleusercontent.com");
        builder.UseSetting("Authentication:Google:ClientSecret", "test-client-secret");

        builder.ConfigureServices(services =>
        {
            // Strip the EF Core options registrations tied to DragonVaultDbContext so we can
            // re-register against the in-memory provider. We deliberately do NOT touch any
            // Identity-store descriptors that happen to be generic-on-DragonVaultDbContext —
            // an over-broad sweep there breaks IUserStore / IRoleStore resolution.
            var optionsServiceTypes = new[]
            {
                typeof(DbContextOptions<DragonVaultDbContext>),
                typeof(DbContextOptions),
            };
            var toRemove = services.Where(d => optionsServiceTypes.Contains(d.ServiceType)).ToList();
            foreach (var d in toRemove) services.Remove(d);

            // Use a private EF Core internal service provider for the in-memory replacement.
            // Without this, EF Core sees both UseSqlServer (production) and
            // UseInMemoryDatabase (tests) registered against the host service provider
            // and throws "Services for database providers ... have been registered" when
            // the first DbContext.Set<T>() resolves. Routing the in-memory provider through
            // its own scoped service provider isolates it cleanly.
            var efSp = new ServiceCollection()
                .AddEntityFrameworkInMemoryDatabase()
                .BuildServiceProvider();

            services.AddDbContext<DragonVaultDbContext>((sp, options) =>
            {
                options.UseInMemoryDatabase(_databaseName);
                options.UseInternalServiceProvider(efSp);
                // EF Core warns when the in-memory provider is used; silence the warning
                // explicitly to keep TreatWarningsAsErrors-friendly.
                options.ConfigureWarnings(w =>
                    w.Ignore(InMemoryEventId.TransactionIgnoredWarning));
                var interceptor = sp.GetRequiredService<AuditSaveChangesInterceptor>();
                options.AddInterceptors(interceptor);
            });

            // Redirect DataProtection keys away from C:\inetpub so the tests don't need
            // privileged write access. Re-issuing AddDataProtection().PersistKeysToFileSystem
            // wins because both calls Configure<KeyManagementOptions>; the last registration
            // overrides the directory.
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(_dpKeysPath))
                .SetApplicationName("dragon-vault-tests");

            // Register a header-driven test auth handler so endpoint tests can hit
            // [Authorize] routes without standing up the Google OAuth pipeline. The
            // handler returns NoResult when X-Test-User-Id is absent, so anonymous
            // requests still fall through Identity's cookie scheme as the next handler
            // in the chain — preserving the production "redirect-to-Login" behavior
            // for the existing Phase B tests.
            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                    TestAuthHandler.SchemeName, _ => { });

            // Make TestAuth the default authenticate scheme so [Authorize] picks it up
            // first; when no X-Test-User-Id header is supplied the handler returns
            // NoResult and ASP.NET Core falls through to the cookie scheme's challenge.
            services.PostConfigure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
            });

            // Replace IAntiforgery with a no-op so [ValidateAntiForgeryToken] passes
            // without the test client first GETting a token-bearing HTML page. Real
            // anti-forgery semantics are exercised manually + by Phase F end-to-end
            // tests; here we focus on payload validation and persistence behavior.
            var antiforgeryDescriptor = services.FirstOrDefault(
                d => d.ServiceType == typeof(Microsoft.AspNetCore.Antiforgery.IAntiforgery));
            if (antiforgeryDescriptor is not null) services.Remove(antiforgeryDescriptor);
            services.AddSingleton<Microsoft.AspNetCore.Antiforgery.IAntiforgery, TestAuth.NoOpAntiforgery>();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            try
            {
                if (Directory.Exists(_dpKeysPath))
                {
                    Directory.Delete(_dpKeysPath, recursive: true);
                }
            }
            catch (IOException)
            {
                // Best-effort cleanup; another test in the same process may still hold a
                // file handle on Windows. Leaving an empty temp directory behind is harmless.
            }
            catch (UnauthorizedAccessException)
            {
                // Same rationale as above.
            }
        }
    }
}
