namespace Skopka.Identity.Roles.Queries;

public interface IIdentityRoleQueryStore<TProfile>
{
    Task<IdentityRolePage> QueryAsync(
        IdentityRoleStoreQuery query,
        CancellationToken ct);
}
