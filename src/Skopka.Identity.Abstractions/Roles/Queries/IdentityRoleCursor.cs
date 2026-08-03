namespace Skopka.Identity.Roles.Queries;

public sealed record IdentityRoleCursor(
    DateTimeOffset CreatedAt,
    Guid Id);
