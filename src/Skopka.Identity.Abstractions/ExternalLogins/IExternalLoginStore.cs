using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.ExternalLogins;

public interface IExternalLoginStore<TProfile>
{
    Task<IdentityUser<TProfile>?> FindActiveUserAsync(
        ExternalLoginKey login,
        CancellationToken ct);

    Task<IReadOnlyList<ExternalLoginInfo>> ListAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> LinkAsync(
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        string newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> UnlinkAsync(
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        string newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct);
}
