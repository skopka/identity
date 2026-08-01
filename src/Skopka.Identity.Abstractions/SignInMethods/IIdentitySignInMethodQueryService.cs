using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.SignInMethods;

public interface IIdentitySignInMethodQueryService<TProfile>
{
    Task<OperationResult<SignInMethodSnapshot>> GetAsync(
        Guid userId,
        CancellationToken ct);
}
