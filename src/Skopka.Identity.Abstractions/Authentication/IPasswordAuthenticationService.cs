using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public interface IPasswordAuthenticationService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> AuthenticateAsync(
        AuthenticatePasswordCommand cmd,
        CancellationToken ct);
}
