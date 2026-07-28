namespace Skopka.Identity.RateLimiting;

public interface IRateLimitBucketStore<TProfile>
{
    Task<RateLimitDecision> CheckAsync(
        string scope,
        string keyHash,
        int permitLimit,
        TimeSpan window,
        DateTimeOffset now,
        CancellationToken ct);

    Task<RateLimitDecision> HitAsync(
        string scope,
        string keyHash,
        int permitLimit,
        TimeSpan window,
        TimeSpan? minimumInterval,
        DateTimeOffset now,
        CancellationToken ct);

    Task ResetAsync(
        string scope,
        string keyHash,
        CancellationToken ct);

    Task<int> PruneAsync(
        DateTimeOffset modifiedBefore,
        int maxCount,
        CancellationToken ct);
}
