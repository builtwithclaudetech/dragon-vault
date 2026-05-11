using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class VaultEntryConfiguration : IEntityTypeConfiguration<VaultEntry>
{
    public void Configure(EntityTypeBuilder<VaultEntry> b)
    {
        b.ToTable("VaultEntries");
        b.HasKey(e => e.Id);

        b.Property(e => e.NameCiphertext).HasColumnType("varbinary(1024)").IsRequired();
        b.Property(e => e.NameIv).HasColumnType("varbinary(12)").IsRequired();
        b.Property(e => e.NameAuthTag).HasColumnType("varbinary(16)").IsRequired();

        b.Property(e => e.TagsCiphertext).HasColumnType("varbinary(2048)");
        b.Property(e => e.TagsIv).HasColumnType("varbinary(12)");
        b.Property(e => e.TagsAuthTag).HasColumnType("varbinary(16)");

        b.Property(e => e.CreatedUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");
        b.Property(e => e.UpdatedUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");

        b.Property(e => e.TagsNormalized).HasDefaultValue(false);

        b.Property(e => e.PasswordHistoryJson).HasColumnType("nvarchar(max)");

        b.Property(e => e.RowVersion).IsRowVersion();

        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_VaultEntries_Users");
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.CreatedBy)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_VaultEntries_Creator");
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.ModifiedBy)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_VaultEntries_Modifier");

        b.HasMany(e => e.Fields).WithOne().HasForeignKey(f => f.EntryId)
            .OnDelete(DeleteBehavior.Restrict);

        b.HasIndex(e => new { e.UserId, e.UpdatedUtc }).HasDatabaseName("IX_VaultEntries_UserId_UpdatedUtc");
    }
}
