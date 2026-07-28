namespace Skopka.Identity.Verification;

public sealed record IssuedVerificationChallenge(
    Guid ChallengeId,
    string Method,
    DateTimeOffset ExpiresAt,
    string? DeliveryCode);
