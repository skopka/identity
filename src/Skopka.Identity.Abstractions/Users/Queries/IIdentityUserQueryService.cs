using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Users.Queries;

public interface IIdentityUserQueryService<TProfile>
{
    Task<OperationResult<IdentityUserPage<TProfile>>> QueryAsync(
        IdentityUserQuery query,
        CancellationToken ct);
}
