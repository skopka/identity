namespace Skopka.Identity.Credentials;

public sealed record VerifyPasswordCommand(
    Guid UserId,
    string Password);
