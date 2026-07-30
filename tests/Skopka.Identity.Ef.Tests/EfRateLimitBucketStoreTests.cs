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
            Partitions("A"),
            permitLimit: 2,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now,
            CancellationToken.None);
        var second = await database.Store.HitAsync(
            "password.client",
            Partitions("A"),
            permitLimit: 2,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now.AddSeconds(1),
            CancellationToken.None);
        var third = await database.Store.HitAsync(
            "password.client",
            Partitions("A"),
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
            Partitions("B"),
            permitLimit: 5,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromSeconds(30),
            database.Now,
            CancellationToken.None);
        var denied = await database.Store.HitAsync(
            "verification.intent",
            Partitions("B"),
            permitLimit: 5,
            TimeSpan.FromMinutes(15),
            TimeSpan.FromSeconds(30),
            database.Now.AddSeconds(10),
            CancellationToken.None);
        var afterCooldown = await database.Store.HitAsync(
            "verification.intent",
            Partitions("B"),
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
                Partitions("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now,
                CancellationToken.None)).IsAllowed);
        Assert.False(
            (await database.Store.CheckAsync(
                "password.account",
                Partitions("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                database.Now.AddSeconds(30),
                CancellationToken.None)).IsAllowed);
        Assert.True(
            (await database.Store.CheckAsync(
                "password.account",
                Partitions("C"),
                permitLimit: 1,
                TimeSpan.FromMinutes(1),
                database.Now.AddMinutes(1),
                CancellationToken.None)).IsAllowed);

        await database.Store.ResetAsync(
            "password.account",
            Partitions("C"),
            CancellationToken.None);

        Assert.Empty(database.Context.RateLimitBuckets);
    }

    [Fact]
    public async Task PruneDeletesOnlyOldestRequestedBatch()
    {
        await using var database = await TestDatabase.CreateAsync();
        await database.Store.HitAsync(
            "password.client",
            Partitions("D"),
            permitLimit: 5,
            TimeSpan.FromMinutes(1),
            minimumInterval: null,
            database.Now,
            CancellationToken.None);
        await database.Store.HitAsync(
            "password.client",
            Partitions("E"),
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

    [Fact]
    public async Task RotationDualWritesBucketsSharedWithPreviousVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var previous = Partitions("F", "v1");
        var rotated = Partitions("F", "v2", "v1");

        Assert.True(
            (await database.Store.HitAsync(
                "password.account",
                previous,
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now,
                CancellationToken.None)).IsAllowed);
        Assert.True(
            (await database.Store.HitAsync(
                "password.account",
                rotated,
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now.AddSeconds(1),
                CancellationToken.None)).IsAllowed);

        Assert.False(
            (await database.Store.HitAsync(
                "password.account",
                previous,
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now.AddSeconds(2),
                CancellationToken.None)).IsAllowed);
        Assert.False(
            (await database.Store.HitAsync(
                "password.account",
                Partitions("F", "v2"),
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                database.Now.AddSeconds(2),
                CancellationToken.None)).IsAllowed);

        var buckets = await database.Context.RateLimitBuckets
            .OrderBy(bucket => bucket.PartitionVersion)
            .ToListAsync();
        Assert.Equal(2, buckets.Count);
        Assert.All(buckets, bucket => Assert.Equal(2, bucket.HitCount));
        Assert.Equal(["v1", "v2"], buckets
            .Select(bucket => bucket.PartitionVersion));
    }

    private static string Hash(string value)
        => Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(value)));

    private static IReadOnlyList<RateLimitPartition> Partitions(
        string value,
        params string[] versions)
    {
        if (versions.Length == 0)
        {
            versions = [RateLimitLimits.LegacyPartitionVersion];
        }

        return versions
            .Select(version => new RateLimitPartition(
                version,
                Hash($"{version}:{value}")))
            .ToArray();
    }

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
