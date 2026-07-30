using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public interface IIdentityUserLookupService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> FindActiveByEmailAsync(
        string email,
        CancellationToken ct);
}
