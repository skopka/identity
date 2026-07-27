using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity;

public interface IIdentityUserStore<TProfile>
{
    Task<IdentityUser<TProfile>?> FindByIdAsync(Guid id, CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> CreateAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> UpdateHandlesAsync(
        Guid userId,
        long expectedVersion,
        UpdatedHandles updated,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> UpdateProfileAsync(
        Guid userId,
        long expectedVersion,
        TProfile profile,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> UpdateSecurityStampAsync(
        Guid userId,
        long expectedVersion,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> UpdateStateAsync(
        Guid userId,
        long expectedVersion,
        DateTimeOffset? deletedAt,
        DateTimeOffset? blockedAt,
        DateTimeOffset? blockedUntil,
        string? newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct);
}
