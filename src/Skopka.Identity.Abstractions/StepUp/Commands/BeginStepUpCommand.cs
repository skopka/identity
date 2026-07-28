namespace Skopka.Identity.StepUp.Commands;

public sealed record BeginStepUpCommand(
    Guid UserId,
    string Action,
    string Binding,
    string Method,
    string? ClientKey = null);
