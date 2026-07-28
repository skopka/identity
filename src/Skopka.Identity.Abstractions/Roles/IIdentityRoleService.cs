using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Roles.Commands;

namespace Skopka.Identity.Roles;

public interface IIdentityRoleService<TProfile>
{
    Task<IdentityRole?> FindByIdAsync(
        Guid roleId,
        CancellationToken ct);

    Task<IdentityRole?> FindByNameAsync(
        string roleName,
        CancellationToken ct);

    Task<OperationResult<IdentityRole>> CreateAsync(
        CreateRoleCommand cmd,
        CancellationToken ct);

    Task<OperationResult<IdentityRole>> UpdateAsync(
        UpdateRoleCommand cmd,
        CancellationToken ct);

    Task<OperationResult> DeleteAsync(
        DeleteRoleCommand cmd,
        CancellationToken ct);

    Task<OperationResult<IReadOnlyList<IdentityRole>>> GetUserRolesAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<bool>> IsUserInRoleAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct);

    Task<OperationResult> AssignAsync(
        AssignRoleCommand cmd,
        CancellationToken ct);

    Task<OperationResult> RemoveAsync(
        RemoveRoleCommand cmd,
        CancellationToken ct);
}
