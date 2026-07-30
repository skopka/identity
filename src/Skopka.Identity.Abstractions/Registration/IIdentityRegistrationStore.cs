using Skopka.Abstraction.OperationResult;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Registration;

public interface IIdentityRegistrationStore<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> CreateWithPasswordAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        string passwordVerifier,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> CreateWithExternalLoginAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        ExternalLoginKey login,
        DateTimeOffset now,
        CancellationToken ct);
}
