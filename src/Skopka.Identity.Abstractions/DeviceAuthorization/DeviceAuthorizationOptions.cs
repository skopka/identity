using Skopka.Identity.Verification;

namespace Skopka.Identity.DeviceAuthorization;

public sealed class DeviceAuthorizationOptions
{
    public TimeSpan RequestLifetime { get; set; } = TimeSpan.FromMinutes(2);

    public int UserCodeLength { get; set; } = 8;

    public int UserCodeGroupSize { get; set; } = 4;

    public string UserCodeAlphabet { get; set; } =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    public string RequiredStepUpMethod { get; set; } =
        VerificationMethods.TimeBasedOneTimePassword;

    public TimeSpan StepUpMaximumAge { get; set; } =
        TimeSpan.FromMinutes(2);

    public int CreateClientPermitLimit { get; set; } = 5;

    public TimeSpan CreateClientWindow { get; set; } =
        TimeSpan.FromMinutes(5);

    public int StatusClientPermitLimit { get; set; } = 120;

    public TimeSpan StatusClientWindow { get; set; } =
        TimeSpan.FromMinutes(2);

    public TimeSpan RetentionAfterExpiration { get; set; } =
        TimeSpan.FromDays(1);

    public int CleanupBatchSize { get; set; } = 500;
}
