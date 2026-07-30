namespace Skopka.Identity.Users.Queries;

public interface IIdentityUserQueryStore<TProfile>
{
    Task<IdentityUserPage<TProfile>> QueryAsync(
        IdentityUserStoreQuery query,
        DateTimeOffset now,
        CancellationToken ct);
}
