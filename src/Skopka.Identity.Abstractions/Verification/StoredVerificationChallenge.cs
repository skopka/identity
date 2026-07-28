namespace Skopka.Identity.Verification;

public sealed record StoredVerificationChallenge(
    Guid Id,
    Guid UserId,
    string Purpose,
    string Binding,
    string Method,
    string Verifier,
    string SecurityStamp,
    int FailedAttemptCount,
    int MaxAttempts,
    VerificationChallengeState State,
    string? ProofHash,
    DateTimeOffset? ProofExpiresAt,
    long Version,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt,
    DateTimeOffset? VerifiedAt,
    DateTimeOffset? ConsumedAt);
