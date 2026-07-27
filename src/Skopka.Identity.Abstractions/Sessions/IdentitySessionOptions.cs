namespace Skopka.Identity.Sessions;

public sealed class IdentitySessionOptions
{
    public TimeSpan AccessTokenLifetime { get; set; } =
        TimeSpan.FromMinutes(15);

    public TimeSpan RefreshSessionLifetime { get; set; } =
        TimeSpan.FromDays(30);

    public TimeSpan RetentionAfterExpiration { get; set; } =
        TimeSpan.FromDays(7);

    public int CleanupBatchSize { get; set; } = 500;
}
