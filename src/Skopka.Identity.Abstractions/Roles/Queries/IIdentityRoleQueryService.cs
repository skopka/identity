using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Roles.Queries;

public interface IIdentityRoleQueryService<TProfile>
{
    Task<OperationResult<IdentityRolePage>> QueryAsync(
        IdentityRoleQuery query,
        CancellationToken ct);
}
