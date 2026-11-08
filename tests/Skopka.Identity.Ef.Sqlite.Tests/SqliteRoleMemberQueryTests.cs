using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using MemberProfile = Skopka.Identity.Ef.Sqlite.Tests.RoleMemberQueryScenario.MemberProfile;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqliteRoleMemberQueryTests
{
    [Fact]
    public async Task RoleMembersArePagedSearchedAndCountedInSqlite()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<MemberProfile>().AddRoles().UseSqlite(connection);
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<SqliteIdentityDbContext<MemberProfile>>()
                .Database.MigrateAsync();
        }

        await RoleMemberQueryScenario.RunAsync(provider);
    }
}
