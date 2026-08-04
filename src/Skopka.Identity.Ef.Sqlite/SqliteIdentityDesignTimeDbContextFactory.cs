using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Skopka.Identity.Ef.Sqlite;

internal sealed class SqliteIdentityDesignTimeDbContextFactory
    : IDesignTimeDbContextFactory<SqliteIdentityDbContext<SqliteIdentityDesignTimeProfile>>
{
    public SqliteIdentityDbContext<SqliteIdentityDesignTimeProfile> CreateDbContext(
        string[] args)
    {
        var options = new DbContextOptionsBuilder<
                SqliteIdentityDbContext<SqliteIdentityDesignTimeProfile>>()
            .UseSqlite("Data Source=skopka_identity_design.db")
            .Options;

        return new SqliteIdentityDbContext<SqliteIdentityDesignTimeProfile>(options);
    }
}

internal sealed record SqliteIdentityDesignTimeProfile;
