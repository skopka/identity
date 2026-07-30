namespace Skopka.Identity.RateLimiting;

public sealed record RateLimitPartition(
    string Version,
    string KeyHash);
