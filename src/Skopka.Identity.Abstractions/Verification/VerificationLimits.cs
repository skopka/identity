namespace Skopka.Identity.Verification;

public static class VerificationLimits
{
    public const int MaximumPurposeLength = 128;
    public const int MaximumBindingLength = 512;
    public const int MaximumMethodLength = 64;
    public const int MaximumVerifierLength = 2_048;
    public const int MaximumProofLength = 512;
}
