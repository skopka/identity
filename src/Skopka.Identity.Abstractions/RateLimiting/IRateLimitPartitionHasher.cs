namespace Skopka.Identity.RateLimiting;

public interface IRateLimitPartitionHasher
{
    string Hash(string scope, string key);
}
