using Microsoft.EntityFrameworkCore;
using PasswordManager.Data;

namespace PasswordManager.Web.Services;

// REQ-077: background hosted service that prunes expired WebAuthnChallenges hourly
// and ErrorLog rows older than 90 days nightly. Resilient to transient DB failures —
// errors are logged and retried on the next cycle; the process never crashes.
// Uses raw SQL (ExecuteSqlRawAsync) for efficiency — no entity loading.
public sealed class PruningHostedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PruningHostedService> _logger;
    private DateOnly _lastErrorLogPruneDate;

    public PruningHostedService(IServiceScopeFactory scopeFactory, ILogger<PruningHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("PruningHostedService starting; waiting 10s for DB readiness");
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        // Run first cleanup cycle immediately after the startup delay so stale data
        // doesn't linger on a fresh boot.
        await PerformCleanupCycleAsync(stoppingToken);

        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await PerformCleanupCycleAsync(stoppingToken);
        }
    }

    private async Task PerformCleanupCycleAsync(CancellationToken ct)
    {
        // Hourly: prune expired WebAuthnChallenges where ExpiresUtc has passed.
        await PruneExpiredChallengesAsync(ct);

        // Nightly (once per UTC calendar day): prune ErrorLog rows older than 90 days.
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        if (today != _lastErrorLogPruneDate)
        {
            await PruneOldErrorLogAsync(ct);
            _lastErrorLogPruneDate = today;
        }
    }

    private async Task PruneExpiredChallengesAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();

            var deleted = await db.Database.ExecuteSqlRawAsync(
                "DELETE FROM WebAuthnChallenges WHERE ExpiresUtc < SYSUTCDATETIME()", ct);

            if (deleted > 0)
            {
                _logger.LogInformation("Pruned {Count} expired WebAuthnChallenge(s)", deleted);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Failed to prune expired WebAuthnChallenges (will retry next cycle)");
        }
    }

    private async Task PruneOldErrorLogAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DragonVaultDbContext>();

            var deleted = await db.Database.ExecuteSqlRawAsync(
                "DELETE FROM ErrorLog WHERE OccurredUtc < DATEADD(DAY, -90, SYSUTCDATETIME())", ct);

            if (deleted > 0)
            {
                _logger.LogInformation("Pruned {Count} old ErrorLog entry(ies)", deleted);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Failed to prune old ErrorLog entries (will retry tomorrow)");
        }
    }
}
