using Skopka.Identity.RateLimiting;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityRateLimiterTests
{
    [Fact]
    public async Task SendsCurrentAndHistoricalPartitionsToStore()
    {
        var store = new FakeBucketStore();
        var limiter = new IdentityRateLimiter<TestProfile>(
            store,
            new FakePartitionHasher(
                "v2",
                ["v1", "v2"]),
            new IdentityRateLimitOptions());
        var request = new RateLimitRequest(
            "password.account",
            "alice@example.com",
            PermitLimit: 5,
            TimeSpan.FromMinutes(1));

        await limiter.HitAsync(request, CancellationToken.None);

        Assert.Equal(
            [
                new RateLimitPartition("v2", new string('2', 64)),
                new RateLimitPartition("v1", new string('1', 64)),
            ],
            store.LastPartitions);
    }

    [Fact]
    public void RejectsHasherWithoutCurrentVersion()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new IdentityRateLimiter<TestProfile>(
                new FakeBucketStore(),
                new FakePartitionHasher(
                    "v2",
                    ["v1"]),
                new IdentityRateLimitOptions()));
    }

    [Fact]
    public void RejectsDuplicateHasherVersions()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new IdentityRateLimiter<TestProfile>(
                new FakeBucketStore(),
                new FakePartitionHasher(
                    "v1",
                    ["v1", "v1"]),
                new IdentityRateLimitOptions()));
    }

    private sealed class FakePartitionHasher(
        string currentVersion,
        IReadOnlyCollection<string> versions)
        : IRateLimitPartitionHasher
    {
        public string CurrentVersion { get; } = currentVersion;

        public IReadOnlyCollection<string> Versions { get; } = versions;

        public string Hash(
            string version,
            string scope,
            string key)
            => version switch
            {
                "v1" => new string('1', 64),
                "v2" => new string('2', 64),
                _ => throw new InvalidOperationException(),
            };
    }

    private sealed class FakeBucketStore
        : IRateLimitBucketStore<TestProfile>
    {
        public IReadOnlyList<RateLimitPartition> LastPartitions { get; private set; }
            = [];

        public Task<RateLimitDecision> CheckAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            int permitLimit,
            TimeSpan window,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastPartitions = partitions;
            return Task.FromResult(new RateLimitDecision(true, null));
        }

        public Task<RateLimitDecision> HitAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            int permitLimit,
            TimeSpan window,
            TimeSpan? minimumInterval,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastPartitions = partitions;
            return Task.FromResult(new RateLimitDecision(true, null));
        }

        public Task ResetAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            CancellationToken ct)
        {
            LastPartitions = partitions;
            return Task.CompletedTask;
        }

        public Task<int> PruneAsync(
            DateTimeOffset modifiedBefore,
            int maxCount,
            CancellationToken ct)
            => Task.FromResult(0);
    }

    public sealed record TestProfile;
}
