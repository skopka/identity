namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserCursor(
    DateTimeOffset CreatedAt,
    Guid Id);
