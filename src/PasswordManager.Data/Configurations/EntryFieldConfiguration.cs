using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class EntryFieldConfiguration : IEntityTypeConfiguration<EntryField>
{
    public void Configure(EntityTypeBuilder<EntryField> b)
    {
        b.ToTable("EntryFields", t =>
            t.HasCheckConstraint("CK_EntryFields_FieldKind",
                "[FieldKind] IN ('username','password','url','notes','totp_secret','custom')"));

        b.HasKey(e => e.Id);

        b.Property(e => e.FieldKind).HasColumnType("varchar(16)").IsRequired();

        // OQ-05: Plaintext custom-field key (nvarchar, not encrypted). The old
        // KeyCiphertext/KeyIv/KeyAuthTag columns are removed in a migration.
        b.Property(e => e.Key).HasColumnType("nvarchar(256)");

        b.Property(e => e.ValueCiphertext).HasColumnType("varbinary(8000)").IsRequired();
        b.Property(e => e.ValueIv).HasColumnType("varbinary(12)").IsRequired();
        b.Property(e => e.ValueAuthTag).HasColumnType("varbinary(16)").IsRequired();

        b.Property(e => e.SortOrder).HasDefaultValue(0);

        b.HasIndex(e => e.EntryId).HasDatabaseName("IX_EntryFields_EntryId");
    }
}
