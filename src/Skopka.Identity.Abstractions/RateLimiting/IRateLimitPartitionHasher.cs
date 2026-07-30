namespace Skopka.Identity.RateLimiting;

public interface IRateLimitPartitionHasher
{
    string CurrentVersion { get; }

    IReadOnlyCollection<string> Versions { get; }

    string Hash(
        string version,
        string scope,
        string key);
}
