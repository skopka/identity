namespace Skopka.Identity.StepUp;

public sealed record StepUpAuthorizationContext(
    Guid UserId,
    string Action,
    string Binding);
