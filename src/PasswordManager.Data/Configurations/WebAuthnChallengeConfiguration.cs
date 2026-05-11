using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class WebAuthnChallengeConfiguration : IEntityTypeConfiguration<WebAuthnChallenge>
{
    public void Configure(EntityTypeBuilder<WebAuthnChallenge> b)
    {
        b.ToTable("WebAuthnChallenges", t =>
            t.HasCheckConstraint("CK_WebAuthnChallenges_Purpose",
                "[Purpose] IN ('register','assert')"));

        b.HasKey(e => e.Id);

        b.Property(e => e.Challenge).HasColumnType("varbinary(64)").IsRequired();
        b.Property(e => e.Purpose).HasColumnType("varchar(16)").IsRequired();

        b.Property(e => e.CreatedUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");
        b.Property(e => e.ExpiresUtc).HasColumnType("datetime2(3)");
        // ConsumedUtc is the single-use latch. Marking it a concurrency token makes EF Core
        // include the ORIGINAL value in the UPDATE WHERE clause, so a concurrent consumer
        // that wins the race causes the loser's SaveChangesAsync to throw
        // DbUpdateConcurrencyException — see WebAuthnChallengeStore.ConsumeAsync. No schema
        // change: this is purely an EF Core-side configuration.
        b.Property(e => e.ConsumedUtc).HasColumnType("datetime2(3)").IsConcurrencyToken();

        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_WebAuthnChallenges_Users");

        b.HasIndex(e => new { e.UserId, e.ExpiresUtc })
            .HasDatabaseName("IX_WebAuthnChallenges_UserId_ExpiresUtc");

        // Filtered index supports the hourly prune sweep efficiently (REQ-077, design §3.3).
        b.HasIndex(e => e.ExpiresUtc)
            .HasDatabaseName("IX_WebAuthnChallenges_ExpiresUtc")
            .HasFilter("[ConsumedUtc] IS NULL");
    }
}
