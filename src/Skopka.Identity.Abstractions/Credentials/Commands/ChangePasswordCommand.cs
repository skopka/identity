namespace Skopka.Identity.Credentials;

public sealed record ChangePasswordCommand(
    Guid UserId,
    long ExpectedVersion,
    string CurrentPassword,
    string NewPassword);
