using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Security;

public interface ISecurityStampService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> RotateAsync(
        RotateSecurityStampCommand cmd,
        CancellationToken ct);

    Task<bool> ValidateAsync(
        Guid userId,
        string securityStamp,
        CancellationToken ct);
}
