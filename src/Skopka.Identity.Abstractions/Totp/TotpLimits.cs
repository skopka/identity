namespace Skopka.Identity.Totp;

public static class TotpLimits
{
    public const int MaximumProtectedSecretLength = 2048;
    public const int RecoveryCodeHashLength = 64;
    public const int MaximumResponseLength = 256;
}
