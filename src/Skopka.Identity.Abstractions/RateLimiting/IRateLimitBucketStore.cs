namespace Skopka.Identity.RateLimiting;

public interface IRateLimitBucketStore<TProfile>
{
    Task<RateLimitDecision> CheckAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        int permitLimit,
        TimeSpan window,
        DateTimeOffset now,
        CancellationToken ct);

    Task<RateLimitDecision> HitAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        int permitLimit,
        TimeSpan window,
        TimeSpan? minimumInterval,
        DateTimeOffset now,
        CancellationToken ct);

    Task ResetAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        CancellationToken ct);

    Task<int> PruneAsync(
        DateTimeOffset modifiedBefore,
        int maxCount,
        CancellationToken ct);
}
