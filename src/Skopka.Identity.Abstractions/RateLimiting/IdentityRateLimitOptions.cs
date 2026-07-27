namespace Skopka.Identity.RateLimiting;

public sealed class IdentityRateLimitOptions
{
    public int PasswordAccountPermitLimit { get; set; } = 5;

    public TimeSpan PasswordAccountWindow { get; set; } =
        TimeSpan.FromMinutes(15);

    public int PasswordClientPermitLimit { get; set; } = 60;

    public TimeSpan PasswordClientWindow { get; set; } =
        TimeSpan.FromMinutes(1);

    public int VerificationAccountPermitLimit { get; set; } = 10;

    public TimeSpan VerificationAccountWindow { get; set; } =
        TimeSpan.FromMinutes(15);

    public int VerificationIntentPermitLimit { get; set; } = 5;

    public TimeSpan VerificationIntentWindow { get; set; } =
        TimeSpan.FromMinutes(15);

    public TimeSpan VerificationResendCooldown { get; set; } =
        TimeSpan.FromSeconds(30);

    public int VerificationClientPermitLimit { get; set; } = 30;

    public TimeSpan VerificationClientWindow { get; set; } =
        TimeSpan.FromMinutes(1);

    public TimeSpan BucketRetention { get; set; } = TimeSpan.FromDays(1);

    public int CleanupBatchSize { get; set; } = 500;
}
