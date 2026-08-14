namespace Skopka.Identity.Totp;

public sealed class TotpOptions
{
    public const int StandardSecretSize = 20;
    public const int StandardDigits = 6;
    public const int StandardPeriodSeconds = 30;
    public const int StandardAllowedTimeStepDrift = 1;

    public TimeSpan EnrollmentLifetime { get; set; } =
        TimeSpan.FromMinutes(10);

    public int RecoveryCodeCount { get; set; } = 10;
}
