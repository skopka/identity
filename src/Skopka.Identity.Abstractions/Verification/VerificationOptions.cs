namespace Skopka.Identity.Verification;

public sealed class VerificationOptions
{
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan ProofLifetime { get; set; } = TimeSpan.FromMinutes(2);

    public int MaxAttempts { get; set; } = 5;

    public int MaximumResponseLength { get; set; } = 256;
}
