namespace Skopka.Identity.Credentials;

public sealed record ResetPasswordCommand(
    Guid UserId,
    string Token,
    string NewPassword);
