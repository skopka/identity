using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ScopeProfile = Skopka.Identity.Ef.Sqlite.Tests.PhoneScopeScenario.ScopeProfile;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqlitePhoneScopeTests
{
    [Fact]
    public async Task OneNumberSignsInOneAccountPerScopeInSqlite()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<ScopeProfile>()
            .UseSqlite(connection)
            .UsePbkdf2PasswordHasher()
            .UseHmacOneTimeCodes("test", Enumerable.Repeat((byte)7, 32).ToArray())
            .UseHmacRateLimiting(
                Enumerable.Repeat((byte)9, 32).ToArray(),
                options => options.VerificationResendCooldown = TimeSpan.FromMilliseconds(1));
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<SqliteIdentityDbContext<ScopeProfile>>()
                .Database.MigrateAsync();
        }

        await PhoneScopeScenario.RunAsync(provider);
    }
}
