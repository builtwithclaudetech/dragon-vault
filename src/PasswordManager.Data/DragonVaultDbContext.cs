using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data;

public class DragonVaultDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
{
    public DragonVaultDbContext(DbContextOptions<DragonVaultDbContext> options) : base(options) { }

    public DbSet<VaultEntry> VaultEntries => Set<VaultEntry>();
    public DbSet<EntryField> EntryFields => Set<EntryField>();
    public DbSet<WebAuthnCredential> WebAuthnCredentials => Set<WebAuthnCredential>();
    public DbSet<WebAuthnChallenge> WebAuthnChallenges => Set<WebAuthnChallenge>();
    public DbSet<ErrorLogEntry> ErrorLog => Set<ErrorLogEntry>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(DragonVaultDbContext).Assembly);

        // REQ-067: every FK is Restrict (no cascades). Identity defaults all of its join-table
        // FKs to Cascade; force them to Restrict so the migration script contains zero
        // ON DELETE CASCADE clauses. Service code handles cascades explicitly when a user is
        // deleted (single-user product — never deleted in v1, but keep the invariant honest).
        foreach (var fk in builder.Model.GetEntityTypes().SelectMany(e => e.GetForeignKeys()))
        {
            fk.DeleteBehavior = DeleteBehavior.Restrict;
        }
    }
}
