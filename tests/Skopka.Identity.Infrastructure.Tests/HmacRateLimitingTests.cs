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

        var first = hasher.Hash("password.account", "alice@example.com");
        var second = hasher.Hash("password.account", "alice@example.com");
        var otherScope = hasher.Hash(
            "verification.account",
            "alice@example.com");

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherScope);
        Assert.Equal(RateLimitLimits.KeyHashLength, first.Length);
        Assert.DoesNotContain("alice", first, StringComparison.OrdinalIgnoreCase);
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
                RandomNumberGenerator.GetBytes(32),
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
    }

    private sealed class FakeRateLimitBucketStore
        : IRateLimitBucketStore<TestProfile>
    {
        public Task<RateLimitDecision> CheckAsync(
            string scope,
            string keyHash,
            int permitLimit,
            TimeSpan window,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(new RateLimitDecision(true, null));

        public Task<RateLimitDecision> HitAsync(
            string scope,
            string keyHash,
            int permitLimit,
            TimeSpan window,
            TimeSpan? minimumInterval,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(new RateLimitDecision(true, null));

        public Task ResetAsync(
            string scope,
            string keyHash,
            CancellationToken ct)
            => Task.CompletedTask;

        public Task<int> PruneAsync(
            DateTimeOffset modifiedBefore,
            int maxCount,
            CancellationToken ct)
            => Task.FromResult(0);
    }

    public sealed record TestProfile;
}
