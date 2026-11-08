using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;
using Xunit;
using ScopeProfile = Skopka.Identity.Ef.PostgreSql.Tests.PhoneScopeScenario.ScopeProfile;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlPhoneScopeTests : IAsyncLifetime
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
    public async Task OneNumberSignsInOneAccountPerScopeInPostgreSql()
    {
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<ScopeProfile>()
            .UsePostgreSql(postgreSql.GetConnectionString())
            .UseHmacOneTimeCodes("test", Enumerable.Repeat((byte)7, 32).ToArray())
            .UseHmacRateLimiting(
                Enumerable.Repeat((byte)9, 32).ToArray(),
                options => options.VerificationResendCooldown = TimeSpan.FromMilliseconds(1));
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<PostgreSqlIdentityDbContext<ScopeProfile>>()
                .Database.MigrateAsync();
        }

        await PhoneScopeScenario.RunAsync(provider);
    }
}
