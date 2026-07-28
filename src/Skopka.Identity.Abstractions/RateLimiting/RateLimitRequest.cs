namespace Skopka.Identity.RateLimiting;

public sealed record RateLimitRequest(
    string Scope,
    string Key,
    int PermitLimit,
    TimeSpan Window,
    TimeSpan? MinimumInterval = null);
