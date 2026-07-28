namespace Skopka.Identity.Verification;

public sealed record VerificationMethodContext(
    Guid ChallengeId,
    Guid UserId,
    string Purpose,
    string Binding);
