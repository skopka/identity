namespace Skopka.Identity.StepUp.Commands;

public sealed record AuthorizeStepUpCommand(
    Guid UserId,
    string Action,
    string Binding,
    Guid ChallengeId,
    string Proof);
