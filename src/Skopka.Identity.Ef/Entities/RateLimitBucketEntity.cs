namespace Skopka.Identity.Ef.Entities;

public sealed class RateLimitBucketEntity
{
    public string Scope { get; set; } = null!;
    public string PartitionVersion { get; set; } = null!;
    public string KeyHash { get; set; } = null!;
    public DateTimeOffset WindowStartedAt { get; set; }
    public int HitCount { get; set; }
    public DateTimeOffset LastHitAt { get; set; }
    public long Version { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}
