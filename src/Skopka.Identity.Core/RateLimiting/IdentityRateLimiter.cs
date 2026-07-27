namespace Skopka.Identity.RateLimiting;

public sealed class IdentityRateLimiter<TProfile>(
    IRateLimitBucketStore<TProfile> store,
    IRateLimitPartitionHasher partitionHasher,
    IdentityRateLimitOptions options)
    : IIdentityRateLimiter<TProfile>
{
    public Task<RateLimitDecision> CheckAsync(
        RateLimitRequest request,
        CancellationToken ct)
    {
        Validate(request);
        return store.CheckAsync(
            request.Scope,
            partitionHasher.Hash(request.Scope, request.Key),
            request.PermitLimit,
            request.Window,
            DateTimeOffset.UtcNow,
            ct);
    }

    public Task<RateLimitDecision> HitAsync(
        RateLimitRequest request,
        CancellationToken ct)
    {
        Validate(request);
        return store.HitAsync(
            request.Scope,
            partitionHasher.Hash(request.Scope, request.Key),
            request.PermitLimit,
            request.Window,
            request.MinimumInterval,
            DateTimeOffset.UtcNow,
            ct);
    }

    public Task ResetAsync(
        string scope,
        string key,
        CancellationToken ct)
    {
        ValidatePartition(scope, key);
        return store.ResetAsync(
            scope,
            partitionHasher.Hash(scope, key),
            ct);
    }

    public Task<int> PruneAsync(CancellationToken ct)
    {
        if (options.BucketRetention <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.BucketRetention));
        }

        if (options.CleanupBatchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.CleanupBatchSize));
        }

        return store.PruneAsync(
            DateTimeOffset.UtcNow.Subtract(options.BucketRetention),
            options.CleanupBatchSize,
            ct);
    }

    private static void Validate(RateLimitRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidatePartition(request.Scope, request.Key);

        if (request.PermitLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.PermitLimit));
        }

        if (request.Window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Window));
        }

        if (request.MinimumInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.MinimumInterval));
        }
    }

    private static void ValidatePartition(string scope, string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (scope.Length > RateLimitLimits.MaximumScopeLength)
        {
            throw new ArgumentException(
                "Rate-limit scope exceeds the supported length.",
                nameof(scope));
        }

        if (key.Length > RateLimitLimits.MaximumKeyLength)
        {
            throw new ArgumentException(
                "Rate-limit key exceeds the supported length.",
                nameof(key));
        }
    }
}
