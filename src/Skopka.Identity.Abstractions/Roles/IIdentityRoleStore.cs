using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Roles;

public interface IIdentityRoleStore<TProfile>
{
    Task<IdentityRole?> FindByIdAsync(
        Guid roleId,
        CancellationToken ct);

    Task<IdentityRole?> FindByNormalizedNameAsync(
        string normalizedName,
        CancellationToken ct);

    Task<OperationResult<IdentityRole>> CreateAsync(
        NewIdentityRole role,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityRole>> UpdateAsync(
        Guid roleId,
        long expectedVersion,
        UpdatedIdentityRole role,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult> DeleteAsync(
        Guid roleId,
        long expectedVersion,
        CancellationToken ct);
}
