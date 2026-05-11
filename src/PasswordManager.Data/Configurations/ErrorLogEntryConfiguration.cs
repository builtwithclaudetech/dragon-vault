using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PasswordManager.Core.Domain;

namespace PasswordManager.Data.Configurations;

public class ErrorLogEntryConfiguration : IEntityTypeConfiguration<ErrorLogEntry>
{
    public void Configure(EntityTypeBuilder<ErrorLogEntry> b)
    {
        b.ToTable("ErrorLog");
        b.HasKey(e => e.Id);
        b.Property(e => e.Id).UseIdentityColumn();

        b.Property(e => e.Source).HasMaxLength(256).IsRequired();
        b.Property(e => e.Message).HasMaxLength(2048).IsRequired();
        b.Property(e => e.Detail).HasColumnType("nvarchar(max)");
        b.Property(e => e.StackTrace).HasColumnType("nvarchar(max)");
        b.Property(e => e.RequestPath).HasMaxLength(512);
        b.Property(e => e.OccurredUtc).HasColumnType("datetime2(3)").HasDefaultValueSql("SYSUTCDATETIME()");

        b.HasIndex(e => e.OccurredUtc).IsDescending().HasDatabaseName("IX_ErrorLog_OccurredUtc");
    }
}
