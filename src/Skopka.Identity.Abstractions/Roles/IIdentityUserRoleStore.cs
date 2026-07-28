using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Roles;

public interface IIdentityUserRoleStore<TProfile>
{
    Task<IReadOnlyList<IdentityRole>> GetRolesAsync(
        Guid userId,
        CancellationToken ct);

    Task<bool> IsInRoleAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct);

    Task<OperationResult> AddAsync(
        Guid userId,
        Guid roleId,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> RemoveAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct);
}
