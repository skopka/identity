using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Xunit;
using Testcontainers.PostgreSql;
namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlTotpResetTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task ResetIsAtomicAndInvalidatesSessionRecoveryAndStaleEnrollment()
    {
        await using var container = new PostgreSqlBuilder("postgres:17-alpine").Build();
        await container.StartAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<TestProfile>().UsePostgreSql(container.GetConnectionString());
        await using var provider = services.BuildServiceProvider();
        await using (var scope = provider.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<PostgreSqlIdentityDbContext<TestProfile>>().Database.MigrateAsync();
        Guid userId;
        string stamp;
        long initialVersion;
        Guid sessionId;
        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await using (var scope = provider.CreateAsyncScope())
        {
            var user = await scope.ServiceProvider.GetRequiredService<IIdentityUserService<TestProfile>>()
                .CreateAsync(new CreateUserCommand<TestProfile>("totp-user", null, null, new TestProfile("test")), CancellationToken.None);
            Assert.True(user.IsSuccess);
            userId = user.Value.Id;
            stamp = user.Value.SecurityStamp;
            initialVersion = user.Value.Version;
            var registry = scope.ServiceProvider.GetRequiredService<IIdentitySessionRegistry<TestProfile>>();
            var session = await registry.RegisterAsync(new RegisterIdentitySessionCommand(userId, stamp), CancellationToken.None);
            Assert.True(session.IsSuccess);
            sessionId = session.Value.SessionId;
        }
        long version;
        long factorVersion;
        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ITotpFactorStore<TestProfile>>();
            Assert.True((await store.CreateOrReplacePendingAsync(new NewTotpEnrollment(userId, id, "protected", now.AddMinutes(10)), initialVersion, now, CancellationToken.None)).IsSuccess);
        }
        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ITotpFactorStore<TestProfile>>();
            var user = await scope.ServiceProvider.GetRequiredService<IIdentityUserStore<TestProfile>>().FindByIdAsync(userId, CancellationToken.None);
            var pending = await store.FindByUserIdAsync(userId, CancellationToken.None);
            Assert.True((await store.EnableAsync(userId, id, pending!.Version, user!.Version, 1, [new string('A', 64)], now, CancellationToken.None)).IsSuccess);
        }
        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ITotpFactorStore<TestProfile>>();
            var user = await scope.ServiceProvider.GetRequiredService<IIdentityUserStore<TestProfile>>().FindByIdAsync(userId, CancellationToken.None);
            var factor = await store.FindByUserIdAsync(userId, CancellationToken.None);
            version = user!.Version;
            factorVersion = factor!.Version;
            Assert.False((await store.ResetAsync(userId, version - 1, id, factorVersion, "new-stamp", now, CancellationToken.None)).IsSuccess);
            Assert.False((await store.ResetAsync(userId, version, Guid.NewGuid(), factorVersion, "new-stamp", now, CancellationToken.None)).IsSuccess);
            Assert.False((await store.ResetAsync(userId, version, id, factorVersion - 1, "new-stamp", now, CancellationToken.None)).IsSuccess);
            Assert.NotNull(await store.FindByUserIdAsync(userId, CancellationToken.None));
        }
        async Task<bool> ResetInIndependentScopeAsync()
        {
            await using var scope = provider.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ITotpFactorStore<TestProfile>>();
            return (await store.ResetAsync(userId, version, id, factorVersion, "new-stamp", now, CancellationToken.None)).IsSuccess;
        }
        var racingResets = await Task.WhenAll(ResetInIndependentScopeAsync(), ResetInIndependentScopeAsync());
        Assert.Single(racingResets, success => success);
        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ITotpFactorStore<TestProfile>>();
            Assert.Null(await store.FindByUserIdAsync(userId, CancellationToken.None));
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext<TestProfile>>();
            Assert.Empty(await db.TotpRecoveryCodes.ToListAsync());
            var user = await scope.ServiceProvider.GetRequiredService<IIdentityUserStore<TestProfile>>().FindByIdAsync(userId, CancellationToken.None);
            Assert.Equal(version + 1, user!.Version);
            Assert.NotEqual(stamp, user.SecurityStamp);
            Assert.False((await store.TryConsumeRecoveryCodeAsync(userId, id, new string('A', 64), now, CancellationToken.None)).Value);
            Assert.False((await store.CreateOrReplacePendingAsync(new NewTotpEnrollment(userId, Guid.NewGuid(), "stale", now.AddMinutes(10)), version, now, CancellationToken.None)).IsSuccess);
            var valid = await scope.ServiceProvider.GetRequiredService<IIdentitySessionRegistry<TestProfile>>()
                .ValidateAsync(new ValidateIdentitySessionCommand(userId, sessionId), CancellationToken.None);
            Assert.False(valid.IsSuccess);
        }
    }
    public sealed record TestProfile(string DisplayName);
}

