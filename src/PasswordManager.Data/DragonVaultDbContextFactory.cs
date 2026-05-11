using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace PasswordManager.Data;

// Used only by `dotnet ef migrations` at design time so the tooling can construct a DbContext
// without booting the Web project. The connection string here is intentionally local — runtime
// configuration comes from appsettings via DI registration in Program.cs.
public class DragonVaultDbContextFactory : IDesignTimeDbContextFactory<DragonVaultDbContext>
{
    public DragonVaultDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<DragonVaultDbContext>()
            .UseSqlServer("Server=localhost;Database=DragonVault;Integrated Security=true;TrustServerCertificate=true;")
            .Options;
        return new DragonVaultDbContext(options);
    }
}
