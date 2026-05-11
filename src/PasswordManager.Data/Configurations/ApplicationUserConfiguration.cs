using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> b)
    {
        b.Property(e => e.GoogleSubject).HasMaxLength(64);
        b.HasIndex(e => e.GoogleSubject).IsUnique().HasFilter("[GoogleSubject] IS NOT NULL");

        b.Property(e => e.DisplayName).HasMaxLength(256);

        b.Property(e => e.KdfSalt).HasColumnType("varbinary(32)");
        b.Property(e => e.KdfIterations).HasDefaultValue(3);
        b.Property(e => e.KdfMemoryKb).HasDefaultValue(65536);
        b.Property(e => e.KdfParallelism).HasDefaultValue(4);
        b.Property(e => e.KdfOutputBytes).HasDefaultValue(32);

        b.Property(e => e.VerifierCiphertext).HasColumnType("varbinary(256)");
        b.Property(e => e.VerifierIv).HasColumnType("varbinary(12)");
        b.Property(e => e.VerifierAuthTag).HasColumnType("varbinary(16)");

        b.Property(e => e.RecoverySalt).HasColumnType("varbinary(16)");
        b.Property(e => e.RecoveryWrappedKey).HasColumnType("varbinary(256)");
        b.Property(e => e.RecoveryWrapIv).HasColumnType("varbinary(12)");
        b.Property(e => e.RecoveryWrapAuthTag).HasColumnType("varbinary(16)");

        // Phase B groundwork for REQ-009 first-sign-in routing; Phase C writes the value.
        b.Property(e => e.MasterPasswordVerifierBlob).HasColumnType("varbinary(256)");

        b.Property(e => e.CreatedUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");
        b.Property(e => e.LastLoginUtc).HasColumnType("datetime2(3)");

        b.Property(e => e.RowVersion).IsRowVersion();
    }
}
