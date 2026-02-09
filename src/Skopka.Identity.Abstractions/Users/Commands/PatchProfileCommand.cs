namespace Skopka.Identity.Users.Commands;

public record PatchProfileCommand<TPatch>(Guid UserId, long ExpectedVersion, TPatch Patch);
