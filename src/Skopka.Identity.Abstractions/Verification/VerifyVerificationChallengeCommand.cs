namespace Skopka.Identity.Verification;

public sealed record VerifyVerificationChallengeCommand(
    Guid ChallengeId,
    Guid UserId,
    string Response);
