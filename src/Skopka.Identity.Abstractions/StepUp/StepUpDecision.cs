namespace Skopka.Identity.StepUp;

public sealed record StepUpDecision(
    Guid UserId,
    string Action,
    string Binding,
    string Purpose,
    Guid ChallengeId,
    string Method,
    int AssuranceLevel,
    DateTimeOffset VerifiedAt,
    DateTimeOffset DecidedAt);
