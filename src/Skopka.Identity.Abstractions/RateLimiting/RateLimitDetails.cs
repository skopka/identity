namespace Skopka.Identity.RateLimiting;

public sealed record RateLimitDetails(DateTimeOffset? RetryAfter);
