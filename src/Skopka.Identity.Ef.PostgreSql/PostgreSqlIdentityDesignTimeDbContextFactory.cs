using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Skopka.Identity.Ef.PostgreSql;

internal sealed class PostgreSqlIdentityDesignTimeDbContextFactory
    : IDesignTimeDbContextFactory<PostgreSqlIdentityDbContext<PostgreSqlIdentityDesignTimeProfile>>
{
    public PostgreSqlIdentityDbContext<PostgreSqlIdentityDesignTimeProfile> CreateDbContext(
        string[] args)
    {
        var options = new DbContextOptionsBuilder<
                PostgreSqlIdentityDbContext<PostgreSqlIdentityDesignTimeProfile>>()
            .UseNpgsql("Host=localhost;Database=skopka_identity_design")
            .Options;

        return new PostgreSqlIdentityDbContext<PostgreSqlIdentityDesignTimeProfile>(options);
    }
}

internal sealed record PostgreSqlIdentityDesignTimeProfile;
