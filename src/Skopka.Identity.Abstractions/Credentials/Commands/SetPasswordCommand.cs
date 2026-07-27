namespace Skopka.Identity.Credentials;

public sealed record SetPasswordCommand(
    Guid UserId,
    long ExpectedVersion,
    string NewPassword);
