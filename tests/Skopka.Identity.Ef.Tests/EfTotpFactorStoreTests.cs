using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Totp;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfTotpFactorStoreTests
{
    [Fact]
    public async Task EnablesFactorAndRejectsCounterAndRecoveryCodeReplay()
    {
        await using var database = await TestDatabase.CreateAsync();
        var enrollmentId = Guid.NewGuid();
        var pending = await database.Store.CreateOrReplacePendingAsync(
            new NewTotpEnrollment(
                database.UserId,
                enrollmentId,
                "protected-secret",
                database.Now.AddMinutes(10)),
            database.Now,
            CancellationToken.None);
        Assert.True(pending.IsSuccess);

        var stored = await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None);
        Assert.NotNull(stored);
        var enabled = await database.Store.EnableAsync(
            database.UserId,
            enrollmentId,
            stored.Version,
            41,
            [Hash('A'), Hash('B')],
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(enabled.IsSuccess);
        Assert.Equal(2, enabled.Value.RecoveryCodesRemaining);

        var firstCounter = await database.Store.TryAcceptCounterAsync(
            database.UserId,
            enrollmentId,
            enabled.Value.Version,
            42,
            database.Now.AddMinutes(2),
            CancellationToken.None);
        Assert.True(firstCounter.IsSuccess);
        Assert.True(firstCounter.Value);

        stored = await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None);
        var replayCounter = await database.Store.TryAcceptCounterAsync(
            database.UserId,
            enrollmentId,
            stored!.Version,
            42,
            database.Now.AddMinutes(2),
            CancellationToken.None);
        Assert.True(replayCounter.IsSuccess);
        Assert.False(replayCounter.Value);

        var firstRecovery = await database.Store.TryConsumeRecoveryCodeAsync(
            database.UserId,
            enrollmentId,
            Hash('A'),
            database.Now.AddMinutes(3),
            CancellationToken.None);
        var replayRecovery = await database.Store.TryConsumeRecoveryCodeAsync(
            database.UserId,
            enrollmentId,
            Hash('A'),
            database.Now.AddMinutes(3),
            CancellationToken.None);
        Assert.True(firstRecovery.IsSuccess);
        Assert.True(firstRecovery.Value);
        Assert.True(replayRecovery.IsSuccess);
        Assert.False(replayRecovery.Value);

        stored = await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None);
        Assert.Equal(1, stored!.RecoveryCodesRemaining);
    }

    [Fact]
    public async Task ReplacingPendingEnrollmentInvalidatesPreviousId()
    {
        await using var database = await TestDatabase.CreateAsync();
        var firstId = Guid.NewGuid();
        await database.Store.CreateOrReplacePendingAsync(
            new NewTotpEnrollment(
                database.UserId,
                firstId,
                "first-protected-secret",
                database.Now.AddMinutes(10)),
            database.Now,
            CancellationToken.None);
        var secondId = Guid.NewGuid();
        await database.Store.CreateOrReplacePendingAsync(
            new NewTotpEnrollment(
                database.UserId,
                secondId,
                "second-protected-secret",
                database.Now.AddMinutes(10)),
            database.Now.AddMinutes(1),
            CancellationToken.None);

        var factor = await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None);
        var stale = await database.Store.EnableAsync(
            database.UserId,
            firstId,
            factor!.Version,
            41,
            [Hash('A')],
            database.Now.AddMinutes(2),
            CancellationToken.None);

        Assert.False(stale.IsSuccess);
        Assert.Equal(secondId, factor.EnrollmentId);
        Assert.Equal("second-protected-secret", factor.ProtectedSecret);
    }

    [Fact]
    public async Task DisableRemovesFactorAndRecoveryCodes()
    {
        await using var database = await TestDatabase.CreateAsync();
        var enrollmentId = Guid.NewGuid();
        await database.Store.CreateOrReplacePendingAsync(
            new NewTotpEnrollment(
                database.UserId,
                enrollmentId,
                "protected-secret",
                database.Now.AddMinutes(10)),
            database.Now,
            CancellationToken.None);
        var factor = await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None);
        await database.Store.EnableAsync(
            database.UserId,
            enrollmentId,
            factor!.Version,
            41,
            [Hash('A')],
            database.Now.AddMinutes(1),
            CancellationToken.None);

        var disabled = await database.Store.DisableAsync(
            database.UserId,
            database.Now.AddMinutes(2),
            CancellationToken.None);

        Assert.True(disabled.IsSuccess);
        Assert.Null(await database.Store.FindByUserIdAsync(
            database.UserId,
            CancellationToken.None));
        Assert.Empty(database.Context.TotpRecoveryCodes);
    }

    private static string Hash(char value) => new(value, 64);

    private sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfTotpFactorStore<TestProfile> store,
        Guid userId,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfTotpFactorStore<TestProfile> Store { get; } = store;
        public Guid UserId { get; } = userId;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();
            var now = new DateTimeOffset(
                2026,
                8,
                14,
                12,
                0,
                0,
                TimeSpan.Zero);
            var user = await new EfIdentityUserStore<TestProfile>(context)
                .CreateAsync(
                    new NewIdentityUser<TestProfile>(
                        "alice",
                        "alice@example.test",
                        null,
                        new TestProfile("Alice"),
                        UserFlags.None,
                        "CURRENT-STAMP"),
                    new NormalizedHandles(
                        "ALICE",
                        "ALICE@EXAMPLE.TEST",
                        null),
                    now,
                    CancellationToken.None);
            Assert.True(user.IsSuccess);
            return new TestDatabase(
                context,
                new EfTotpFactorStore<TestProfile>(context),
                user.Value.Id,
                now);
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
