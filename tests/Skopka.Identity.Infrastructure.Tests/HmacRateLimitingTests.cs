using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.RateLimiting;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class HmacRateLimitingTests
{
    [Fact]
    public void PartitionHasherIsDeterministicAndScopeBound()
    {
        using var hasher = new HmacRateLimitPartitionHasher(
            RandomNumberGenerator.GetBytes(32));

        var first = hasher.Hash(
            RateLimitLimits.LegacyPartitionVersion,
            "password.account",
            "alice@example.com");
        var second = hasher.Hash(
            RateLimitLimits.LegacyPartitionVersion,
            "password.account",
            "alice@example.com");
        var otherScope = hasher.Hash(
            RateLimitLimits.LegacyPartitionVersion,
            "verification.account",
            "alice@example.com");

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherScope);
        Assert.Equal(RateLimitLimits.KeyHashLength, first.Length);
        Assert.DoesNotContain("alice", first, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(
            RateLimitLimits.LegacyPartitionVersion,
            hasher.CurrentVersion);
        Assert.Equal(
            [RateLimitLimits.LegacyPartitionVersion],
            hasher.Versions);
    }

    [Fact]
    public void PartitionHasherSupportsVersionedKeyRotation()
    {
        using var hasher = new HmacRateLimitPartitionHasher(
            "v2",
            new Dictionary<string, byte[]>
            {
                ["v1"] = RandomNumberGenerator.GetBytes(32),
                ["v2"] = RandomNumberGenerator.GetBytes(32),
            });

        var previous = hasher.Hash(
            "v1",
            "password.account",
            "alice@example.com");
        var current = hasher.Hash(
            "v2",
            "password.account",
            "alice@example.com");

        Assert.Equal("v2", hasher.CurrentVersion);
        Assert.Equal(["v2", "v1"], hasher.Versions);
        Assert.NotEqual(previous, current);
        Assert.Throws<ArgumentException>(() => hasher.Hash(
            "v3",
            "password.account",
            "alice@example.com"));
    }

    [Fact]
    public void PartitionHasherRejectsInvalidRotationConfiguration()
    {
        Assert.Throws<ArgumentException>(() =>
            new HmacRateLimitPartitionHasher(
                "v2",
                new Dictionary<string, byte[]>
                {
                    ["v1"] = RandomNumberGenerator.GetBytes(32),
                }));
        Assert.Throws<ArgumentException>(() =>
            new HmacRateLimitPartitionHasher(
                "v 1",
                new Dictionary<string, byte[]>
                {
                    ["v 1"] = RandomNumberGenerator.GetBytes(32),
                }));
        Assert.Throws<ArgumentException>(() =>
            new HmacRateLimitPartitionHasher(
                "v1",
                new Dictionary<string, byte[]>
                {
                    ["v1"] = RandomNumberGenerator.GetBytes(31),
                }));
    }

    [Fact]
    public void DependencyInjectionRegistersPersistentRateLimiter()
    {
        var services = new ServiceCollection();
        services.AddSingleton<
            IRateLimitBucketStore<TestProfile>,
            FakeRateLimitBucketStore>();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseHmacRateLimiting(
                "v2",
                new Dictionary<string, byte[]>
                {
                    ["v1"] = RandomNumberGenerator.GetBytes(32),
                    ["v2"] = RandomNumberGenerator.GetBytes(32),
                },
                options =>
                {
                    options.PasswordAccountPermitLimit = 3;
                    options.VerificationResendCooldown =
                        TimeSpan.FromSeconds(45);
                });

        using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.CreateScope();

        Assert.IsType<IdentityRateLimiter<TestProfile>>(
            scope.ServiceProvider.GetRequiredService<
                IIdentityRateLimiter<TestProfile>>());
        var options = serviceProvider.GetRequiredService<
            IdentityRateLimitOptions>();
        Assert.Equal(3, options.PasswordAccountPermitLimit);
        Assert.Equal(
            TimeSpan.FromSeconds(45),
            options.VerificationResendCooldown);
        var hasher = serviceProvider.GetRequiredService<
            IRateLimitPartitionHasher>();
        Assert.Equal("v2", hasher.CurrentVersion);
        Assert.Equal(["v2", "v1"], hasher.Versions);
    }

    [Fact]
    public void DependencyInjectionAcceptsNonHmacPartitionHasher()
    {
        var services = new ServiceCollection();
        services.AddSingleton<
            IRateLimitBucketStore<TestProfile>,
            FakeRateLimitBucketStore>();
        var hasher = new FakePartitionHasher();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseRateLimiting(hasher);

        using var provider = services.BuildServiceProvider();

        Assert.Same(
            hasher,
            provider.GetRequiredService<IRateLimitPartitionHasher>());
    }

    [Fact]
    public void DependencyInjectionDisposesOwnedHmacHasher()
    {
        var services = new ServiceCollection();
        services.AddSingleton<
            IRateLimitBucketStore<TestProfile>,
            FakeRateLimitBucketStore>();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UseHmacRateLimiting(
                RandomNumberGenerator.GetBytes(32));
        var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<
            IRateLimitPartitionHasher>();

        provider.Dispose();

        Assert.Throws<ObjectDisposedException>(() => hasher.Hash(
            RateLimitLimits.LegacyPartitionVersion,
            "password.account",
            "alice@example.com"));
    }

    private sealed class FakeRateLimitBucketStore
        : IRateLimitBucketStore<TestProfile>
    {
        public Task<RateLimitDecision> CheckAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            int permitLimit,
            TimeSpan window,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(new RateLimitDecision(true, null));

        public Task<RateLimitDecision> HitAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            int permitLimit,
            TimeSpan window,
            TimeSpan? minimumInterval,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(new RateLimitDecision(true, null));

        public Task ResetAsync(
            string scope,
            IReadOnlyList<RateLimitPartition> partitions,
            CancellationToken ct)
            => Task.CompletedTask;

        public Task<int> PruneAsync(
            DateTimeOffset modifiedBefore,
            int maxCount,
            CancellationToken ct)
            => Task.FromResult(0);
    }

    private sealed class FakePartitionHasher : IRateLimitPartitionHasher
    {
        public string CurrentVersion => "custom-v1";

        public IReadOnlyCollection<string> Versions => ["custom-v1"];

        public string Hash(
            string version,
            string scope,
            string key)
            => Convert.ToHexString(
                SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        $"{version}:{scope}:{key}")));
    }

    public sealed record TestProfile;
}
