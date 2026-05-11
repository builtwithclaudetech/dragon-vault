using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Moq;
using PasswordManager.Core.Domain;
using PasswordManager.Core.Interfaces;
using PasswordManager.Data;

namespace PasswordManager.Tests.Unit.Data;

// Interceptor is exercised end-to-end via a real DbContext on the in-memory provider.
// Each test gets a fresh, uniquely-named in-memory database so state cannot leak between Facts.
public sealed class AuditSaveChangesInterceptorTests
{
    private static DragonVaultDbContext BuildContext(string dbName, ICurrentUserAccessor accessor)
    {
        var options = new DbContextOptionsBuilder<DragonVaultDbContext>()
            .UseInMemoryDatabase(databaseName: dbName)
            .AddInterceptors(new AuditSaveChangesInterceptor(accessor))
            .Options;
        return new DragonVaultDbContext(options);
    }

    private static ICurrentUserAccessor AccessorReturning(Guid? userId)
    {
        var mock = new Mock<ICurrentUserAccessor>();
        mock.Setup(a => a.GetCurrentUserId()).Returns(userId);
        return mock.Object;
    }

    private static VaultEntry NewEntry(Guid userId) => new()
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        NameCiphertext = [1, 2, 3],
        NameIv = [4, 5, 6],
        NameAuthTag = [7, 8, 9],
        // Sentinel values so we can assert the interceptor wrote a fresh UpdatedUtc.
        CreatedUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        UpdatedUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
    };

    [Fact]
    public async Task SaveChanges_OnAdd_StampsCreatedAndModifiedFromAccessor()
    {
        var userId = Guid.NewGuid();
        var dbName = $"add-stamps-{Guid.NewGuid()}";
        await using var db = BuildContext(dbName, AccessorReturning(userId));

        var entry = NewEntry(userId);
        entry.CreatedBy = null;
        entry.ModifiedBy = null;

        var before = DateTime.UtcNow.AddMilliseconds(-5);
        db.VaultEntries.Add(entry);
        await db.SaveChangesAsync();
        var after = DateTime.UtcNow.AddMilliseconds(5);

        entry.CreatedBy.Should().Be(userId);
        entry.ModifiedBy.Should().Be(userId);
        entry.UpdatedUtc.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
    }

    [Fact]
    public async Task SaveChanges_OnAdd_PreservesExistingCreatedBy()
    {
        // ??= semantics: if CreatedBy is already populated (e.g. backfill / data import) the
        // interceptor must not clobber it. ModifiedBy is unconditionally set to the actor.
        var actor = Guid.NewGuid();
        var preset = Guid.NewGuid();
        var dbName = $"add-preserve-{Guid.NewGuid()}";
        await using var db = BuildContext(dbName, AccessorReturning(actor));

        var entry = NewEntry(actor);
        entry.CreatedBy = preset;

        db.VaultEntries.Add(entry);
        await db.SaveChangesAsync();

        entry.CreatedBy.Should().Be(preset, "the interceptor uses ??= and must preserve a pre-set value");
        entry.ModifiedBy.Should().Be(actor);
    }

    [Fact]
    public async Task SaveChanges_OnModify_TouchesModifiedAndUpdatedUtc_LeavesCreatedAlone()
    {
        // Share the in-memory DB across two scoped contexts: one seeds (creator), the other modifies (modifier).
        var dbName = $"modify-roundtrip-{Guid.NewGuid()}";
        var creator = Guid.NewGuid();
        var modifier = Guid.NewGuid();

        Guid entryId;
        Guid? seededCreatedBy;
        DateTime seededCreatedUtc;
        DateTime seededUpdatedUtc;

        await using (var seedDb = BuildContext(dbName, AccessorReturning(creator)))
        {
            var entry = NewEntry(creator);
            entry.CreatedBy = null;
            seedDb.VaultEntries.Add(entry);
            await seedDb.SaveChangesAsync();
            entryId = entry.Id;
            seededCreatedBy = entry.CreatedBy;
            seededCreatedUtc = entry.CreatedUtc;
            seededUpdatedUtc = entry.UpdatedUtc;
        }

        seededCreatedBy.Should().Be(creator);

        await using (var modifyDb = BuildContext(dbName, AccessorReturning(modifier)))
        {
            var loaded = await modifyDb.VaultEntries.FindAsync(entryId);
            loaded.Should().NotBeNull();
            loaded!.NameCiphertext = [9, 9, 9];

            var before = DateTime.UtcNow.AddMilliseconds(-5);
            await modifyDb.SaveChangesAsync();
            var after = DateTime.UtcNow.AddMilliseconds(5);

            loaded.CreatedBy.Should().Be(creator, "Modify path must not touch CreatedBy");
            loaded.CreatedUtc.Should().Be(seededCreatedUtc, "Modify path must not touch CreatedUtc");
            loaded.ModifiedBy.Should().Be(modifier);
            loaded.UpdatedUtc.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
            loaded.UpdatedUtc.Should().BeAfter(seededUpdatedUtc);
        }
    }

    [Fact]
    public async Task SaveChanges_AccessorReturnsNull_DoesNotThrow_LeavesUserColumnsNull()
    {
        var dbName = $"null-accessor-{Guid.NewGuid()}";
        await using var db = BuildContext(dbName, AccessorReturning(userId: null));

        var entry = NewEntry(Guid.NewGuid());
        entry.CreatedBy = null;
        entry.ModifiedBy = null;

        var act = async () =>
        {
            db.VaultEntries.Add(entry);
            await db.SaveChangesAsync();
        };

        await act.Should().NotThrowAsync();
        entry.CreatedBy.Should().BeNull();
        entry.ModifiedBy.Should().BeNull();
        // UpdatedUtc is non-nullable and has no actor dependency, so it's still stamped.
        entry.UpdatedUtc.Should().BeAfter(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public async Task SaveChanges_NoVaultEntries_DoesNothingAndDoesNotThrow()
    {
        // Empty unit-of-work — interceptor must be a no-op and not throw.
        var dbName = $"empty-uow-{Guid.NewGuid()}";
        await using var db = BuildContext(dbName, AccessorReturning(Guid.NewGuid()));

        var act = async () => await db.SaveChangesAsync();

        await act.Should().NotThrowAsync();
    }
}
