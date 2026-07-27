using Microsoft.EntityFrameworkCore;
using Skopka.Identity.RateLimiting;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfRateLimitBucketStoreTests
{
    [Fact]
    public async Task FixedWindowRejectsHitsAfterPermitLimit()
    {
        await using var database = await TestDatabase.CreateAsync();

        var first = await database.Store.HitAsync(
            "password.client",
            Hash("A"),
            permitLimit: 2,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now,
            CancellationToken.None);
        var second = await database.Store.HitAsync(
            "password.client",
            Hash("A"),
            permitLimit: 2,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now.AddSeconds(1),
            CancellationToken.None);
        var third = await database.Store.HitAsync(
            "password.client",
            Hash("A"),
            permitLimit: 2,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now.AddSeconds(2),
            CancellationToken.None);

        Assert.True(first.IsAllowed);
        Assert.True(second.IsAllowed);
        Assert.False(third.IsAllowed);
        Assert.Equal(database.Now.AddMinutes(1), third.RetryAfter);
    }

    [Fact]
    public async Task MinimumIntervalDoesNotMoveAfterDeniedHit()
    {
        await using var database = await TestDatabase.CreateAsync();

        var first = await database.Store.HitAsync(
            "verification.intent",
            Hash("B"),
            permitLimit: 5,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromSeconds(30),
            database.Now,
            CancellationToken.None);
        var denied = await database.Store.HitAsync(
            "verification.intent",
            Hash("B"),
            permitLimit: 5,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromSeconds(30),
            database.Now.AddSeconds(10),
            CancellationToken.None);
        var afterCooldown = await database.Store.HitAsync(
            "verification.intent",
            Hash("B"),
            permitLimit: 5,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromSeconds(30),
            database.Now.AddSeconds(30),
            CancellationToken.None);

        Assert.True(first.IsAllowed);
        Assert.False(denied.IsAllowed);
        Assert.Equal(database.Now.AddSeconds(30), denied.RetryAfter);
        Assert.True(afterCooldown.IsAllowed);
    }

    [Fact]
    public async Task WindowExpiryAndResetAllowNewHit()
    {
        await using var database = await TestDatabase.CreateAsync();

        Assert.True(
            (await database.Store.HitAsync(
                "password.account",
                Hash("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now,
                CancellationToken.None)).IsAllowed);
        Assert.False(
            (await database.Store.CheckAsync(
                "password.account",
                Hash("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                database.Now.AddSeconds(30),
                CancellationToken.None)).IsAllowed);
        Assert.True(
            (await database.Store.CheckAsync(
                "password.account",
                Hash("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                database.Now.AddMinutes(1),
                CancellationToken.None)).IsAllowed);

        await database.Store.ResetAsync(
            "password.account",
            Hash("C"),
            CancellationToken.None);

        Assert.Empty(database.Context.RateLimitBuckets);
    }

    [Fact]
    public async Task PruneDeletesOnlyOldestRequestedBatch()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.Store.HitAsync(
            "password.client",
            Hash("D"),
            permitLimit: 5,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now,
            CancellationToken.None);
        await database.Store.HitAsync(
            "password.client",
            Hash("E"),
            permitLimit: 5,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        var removed = await database.Store.PruneAsync(
            database.Now.AddMinutes(2),
            maxCount: 1,
            CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Single(database.Context.RateLimitBuckets);
    }

    private static string Hash(string value)
        => value.PadRight(RateLimitLimits.KeyHashLength, '0');

    public sealed record TestProfile;

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfRateLimitBucketStore<TestProfile> store,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfRateLimitBucketStore<TestProfile> Store { get; } = store;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            return new TestDatabase(
                context,
                new EfRateLimitBucketStore<TestProfile>(context),
                new DateTimeOffset(
                    2026,
                    7,
                    28,
                    12,
                    0,
                    0,
                    TimeSpan.Zero));
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
