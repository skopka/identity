namespace Skopka.Identity.RateLimiting;

public interface IIdentityRateLimiter<TProfile>
{
    Task<RateLimitDecision> CheckAsync(
        RateLimitRequest request,
        CancellationToken ct);

    Task<RateLimitDecision> HitAsync(
        RateLimitRequest request,
        CancellationToken ct);

    Task ResetAsync(
        string scope,
        string key,
        CancellationToken ct);

    Task<int> PruneAsync(CancellationToken ct);
}
