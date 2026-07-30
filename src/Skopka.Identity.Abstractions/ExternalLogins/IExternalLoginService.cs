using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.ExternalLogins;

public interface IExternalLoginService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> ResolveAsync(
        ExternalLoginKey login,
        CancellationToken ct);

    Task<OperationResult<IReadOnlyList<ExternalLoginInfo>>> ListAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> LinkAsync(
        LinkExternalLoginCommand command,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> UnlinkAsync(
        UnlinkExternalLoginCommand command,
        CancellationToken ct);
}
