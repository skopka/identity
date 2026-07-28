namespace Skopka.Identity.RateLimiting;

public sealed record RateLimitDecision(
    bool IsAllowed,
    DateTimeOffset? RetryAfter);
