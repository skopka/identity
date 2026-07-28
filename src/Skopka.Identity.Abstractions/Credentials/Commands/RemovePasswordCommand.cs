namespace Skopka.Identity.Credentials;

public sealed record RemovePasswordCommand(
    Guid UserId,
    long ExpectedVersion);
