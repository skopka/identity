namespace Skopka.Identity.Verification;

public sealed record BeginVerificationCommand(
    Guid UserId,
    string Purpose,
    string Binding,
    string Method,
    string? ClientKey = null);
