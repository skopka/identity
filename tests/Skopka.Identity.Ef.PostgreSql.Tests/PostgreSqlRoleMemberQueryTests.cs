using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;
using Xunit;
using MemberProfile = Skopka.Identity.Ef.PostgreSql.Tests.RoleMemberQueryScenario.MemberProfile;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlRoleMemberQueryTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgreSql = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("skopka_identity")
        .WithUsername("postgres")
        .WithPassword("postgres")
        .Build();

    public Task InitializeAsync() => postgreSql.StartAsync();

    public async Task DisposeAsync() => await postgreSql.DisposeAsync();

    [Fact]
    [Trait("Category", "Integration")]
    public async Task RoleMembersArePagedSearchedAndCountedInPostgreSql()
    {
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<MemberProfile>().AddRoles().UsePostgreSql(postgreSql.GetConnectionString());
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<PostgreSqlIdentityDbContext<MemberProfile>>()
                .Database.MigrateAsync();
        }

        await RoleMemberQueryScenario.RunAsync(provider);
    }
}
