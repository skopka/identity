namespace Skopka.Identity.Verification;

public sealed record VerificationProof(
    Guid ChallengeId,
    string Token,
    DateTimeOffset ExpiresAt,
    string Method = VerificationMethods.OneTimeCode);
