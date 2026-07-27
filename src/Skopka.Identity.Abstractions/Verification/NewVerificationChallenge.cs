namespace Skopka.Identity.Verification;

public sealed record NewVerificationChallenge(
    Guid Id,
    Guid UserId,
    string Purpose,
    string Binding,
    string Method,
    string Verifier,
    string SecurityStamp,
    int MaxAttempts,
    DateTimeOffset ExpiresAt);
