namespace Skopka.Identity.RateLimiting;

public static class RateLimitLimits
{
    public const int MaximumScopeLength = 64;
    public const int MaximumKeyLength = 1_024;
    public const int MaximumClientKeyLength = 256;
    public const int KeyHashLength = 64;
    public const int MaximumPartitionVersionLength = 64;
    public const int MaximumPartitionVersions = 8;
    public const string LegacyPartitionVersion = "legacy";
}
