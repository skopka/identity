namespace Skopka.Identity.Verification;

public sealed record ConsumeVerificationProofCommand(
    Guid ChallengeId,
    Guid UserId,
    string Purpose,
    string Binding,
    string Proof);
