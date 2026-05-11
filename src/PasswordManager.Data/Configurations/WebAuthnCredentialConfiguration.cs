using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class WebAuthnCredentialConfiguration : IEntityTypeConfiguration<WebAuthnCredential>
{
    public void Configure(EntityTypeBuilder<WebAuthnCredential> b)
    {
        b.ToTable("WebAuthnCredentials", t =>
            t.HasCheckConstraint("CK_WebAuthnCredentials_WrapMethod",
                "[WrapMethod] IN ('largeBlob','prf')"));

        b.HasKey(e => e.Id);

        b.Property(e => e.CredentialId).HasColumnType("varbinary(512)").IsRequired();
        b.Property(e => e.PublicKeyCose).HasColumnType("varbinary(1024)").IsRequired();
        b.Property(e => e.SignCount).HasDefaultValue(0L);
        b.Property(e => e.Transports).HasMaxLength(64);
        b.Property(e => e.Nickname).HasMaxLength(64);

        b.Property(e => e.WrappedKeyCiphertext).HasColumnType("varbinary(256)").IsRequired();
        b.Property(e => e.WrappedKeyIv).HasColumnType("varbinary(12)").IsRequired();
        b.Property(e => e.WrappedKeyAuthTag).HasColumnType("varbinary(16)").IsRequired();

        b.Property(e => e.WrapMethod).HasColumnType("varchar(16)").IsRequired();

        b.Property(e => e.CreatedUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");
        b.Property(e => e.LastUsedUtc).HasColumnType("datetime2(3)");

        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_WebAuthnCredentials_Users");

        b.HasIndex(e => e.CredentialId).IsUnique().HasDatabaseName("UQ_WebAuthnCredentials_CredentialId");
        b.HasIndex(e => e.UserId).HasDatabaseName("IX_WebAuthnCredentials_UserId");
    }
}
