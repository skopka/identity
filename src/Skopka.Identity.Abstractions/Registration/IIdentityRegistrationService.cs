using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Registration;

public interface IIdentityRegistrationService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> RegisterPasswordAsync(
        RegisterPasswordUserCommand<TProfile> command,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> RegisterExternalAsync(
        RegisterExternalUserCommand<TProfile> command,
        CancellationToken ct);
}
