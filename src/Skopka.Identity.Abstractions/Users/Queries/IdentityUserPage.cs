namespace Skopka.Identity.Users.Queries;

public sealed record IdentityUserPage<TProfile>(
    IReadOnlyList<IdentityUser<TProfile>> Items,
    IdentityUserCursor? NextCursor);
