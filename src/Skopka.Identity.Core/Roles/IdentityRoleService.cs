using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Roles.Commands;
using Skopka.Identity.Users;

namespace Skopka.Identity.Roles;

public sealed class IdentityRoleService<TProfile>(
    IIdentityRoleStore<TProfile> roleStore,
    IIdentityUserRoleStore<TProfile> userRoleStore,
    IIdentityUserStore<TProfile> userStore,
    IIdentityRoleNormalizer normalizer,
    IUserOperationPolicy userPolicy,
    IIdentityMetrics metrics)
    : IIdentityRoleService<TProfile>
{
    public async Task<IdentityRole?> FindByIdAsync(
        Guid roleId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.find_by_id");
        var role = await roleStore.FindByIdAsync(roleId, ct);
        op.Success();
        return role;
    }

    public async Task<IdentityRole?> FindByNameAsync(
        string roleName,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.find_by_name");
        var normalizedName = normalizer.NormalizeName(roleName);
        if (normalizedName is null)
        {
            op.Success();
            return null;
        }

        var role = await roleStore.FindByNormalizedNameAsync(normalizedName, ct);
        op.Success();
        return role;
    }

    public async Task<OperationResult<IdentityRole>> CreateAsync(
        CreateRoleCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.create");

        var validation = ValidateRole(cmd.Name, cmd.Description);
        if (validation is not null)
        {
            return Fail<IdentityRole>(op, validation);
        }

        var name = cmd.Name.Trim();
        var normalizedName = normalizer.NormalizeName(name);
        if (normalizedName is null)
        {
            return Fail<IdentityRole>(
                op,
                IdentityRoleErrors.Validation(
                    "name",
                    "Role name cannot normalize to an empty value."));
        }

        var existing = await roleStore.FindByNormalizedNameAsync(normalizedName, ct);
        if (existing is not null)
        {
            return Fail<IdentityRole>(op, IdentityRoleErrors.DuplicateName());
        }

        var hierarchyError = await ValidateParentAsync(null, cmd.ParentId, ct);
        if (hierarchyError is not null)
        {
            return Fail<IdentityRole>(op, hierarchyError);
        }

        var result = await roleStore.CreateAsync(
            new NewIdentityRole(
                name,
                normalizedName,
                NormalizeDescription(cmd.Description),
                cmd.ParentId),
            DateTimeOffset.UtcNow,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult<IdentityRole>> UpdateAsync(
        UpdateRoleCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.update");

        var validation = ValidateRole(cmd.Name, cmd.Description);
        if (validation is not null)
        {
            return Fail<IdentityRole>(op, validation);
        }

        var role = await roleStore.FindByIdAsync(cmd.RoleId, ct);
        if (role is null)
        {
            return Fail<IdentityRole>(op, IdentityRoleErrors.NotFound());
        }

        if (role.Version != cmd.ExpectedVersion)
        {
            return Fail<IdentityRole>(op, IdentityErrors.Concurrency());
        }

        var hierarchyError = await ValidateParentAsync(cmd.RoleId, cmd.ParentId, ct);
        if (hierarchyError is not null)
        {
            return Fail<IdentityRole>(op, hierarchyError);
        }

        var name = cmd.Name.Trim();
        var normalizedName = normalizer.NormalizeName(name);
        if (normalizedName is null)
        {
            return Fail<IdentityRole>(
                op,
                IdentityRoleErrors.Validation(
                    "name",
                    "Role name cannot normalize to an empty value."));
        }

        var duplicate = await roleStore.FindByNormalizedNameAsync(normalizedName, ct);
        if (duplicate is not null && duplicate.Id != role.Id)
        {
            return Fail<IdentityRole>(op, IdentityRoleErrors.DuplicateName());
        }

        var result = await roleStore.UpdateAsync(
            role.Id,
            cmd.ExpectedVersion,
            new UpdatedIdentityRole(
                name,
                normalizedName,
                NormalizeDescription(cmd.Description),
                cmd.ParentId),
            DateTimeOffset.UtcNow,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult> DeleteAsync(
        DeleteRoleCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.delete");

        var role = await roleStore.FindByIdAsync(cmd.RoleId, ct);
        if (role is null)
        {
            return Fail(op, IdentityRoleErrors.NotFound());
        }

        if (role.Version != cmd.ExpectedVersion)
        {
            return Fail(op, IdentityErrors.Concurrency());
        }

        var result = await roleStore.DeleteAsync(
            role.Id,
            cmd.ExpectedVersion,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult<IReadOnlyList<IdentityRole>>>
        GetUserRolesAsync(
            Guid userId,
            CancellationToken ct)
    {
        using var op = metrics.Begin("role.get_user_roles");

        var userError = await ValidateUserAsync(userId, requireMutable: false, ct);
        if (userError is not null)
        {
            return Fail<IReadOnlyList<IdentityRole>>(op, userError);
        }

        var roles = await userRoleStore.GetRolesAsync(userId, ct);
        op.Success();
        return OperationResultFactory.Success(roles);
    }

    public async Task<OperationResult<bool>> IsUserInRoleAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("role.is_user_in_role");

        var userError = await ValidateUserAsync(userId, requireMutable: false, ct);
        if (userError is not null)
        {
            return Fail<bool>(op, userError);
        }

        if (await roleStore.FindByIdAsync(roleId, ct) is null)
        {
            return Fail<bool>(op, IdentityRoleErrors.NotFound());
        }

        var isInRole = await userRoleStore.IsInRoleAsync(userId, roleId, ct);
        op.Success();
        return OperationResultFactory.Success(isInRole);
    }

    public Task<OperationResult> AssignAsync(
        AssignRoleCommand cmd,
        CancellationToken ct)
        => ChangeMembershipAsync(
            "role.assign",
            cmd.UserId,
            cmd.RoleId,
            add: true,
            ct);

    public Task<OperationResult> RemoveAsync(
        RemoveRoleCommand cmd,
        CancellationToken ct)
        => ChangeMembershipAsync(
            "role.remove",
            cmd.UserId,
            cmd.RoleId,
            add: false,
            ct);

    private async Task<OperationResult> ChangeMembershipAsync(
        string operation,
        Guid userId,
        Guid roleId,
        bool add,
        CancellationToken ct)
    {
        using var op = metrics.Begin(operation);

        var userError = await ValidateUserAsync(userId, requireMutable: true, ct);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        if (await roleStore.FindByIdAsync(roleId, ct) is null)
        {
            return Fail(op, IdentityRoleErrors.NotFound());
        }

        var result = add
            ? await userRoleStore.AddAsync(
                userId,
                roleId,
                DateTimeOffset.UtcNow,
                ct)
            : await userRoleStore.RemoveAsync(userId, roleId, ct);

        return Finish(op, result);
    }

    private async Task<Error?> ValidateParentAsync(
        Guid? roleId,
        Guid? parentId,
        CancellationToken ct)
    {
        if (parentId is null)
        {
            return null;
        }

        var visited = new HashSet<Guid>();
        if (roleId is not null)
        {
            visited.Add(roleId.Value);
        }

        var currentId = parentId;
        while (currentId is not null)
        {
            if (!visited.Add(currentId.Value))
            {
                return IdentityRoleErrors.Validation(
                    "parentId",
                    "Role hierarchy cannot contain a cycle.");
            }

            var current = await roleStore.FindByIdAsync(currentId.Value, ct);
            if (current is null)
            {
                return IdentityRoleErrors.NotFound();
            }

            currentId = current.ParentId;
        }

        return null;
    }

    private async Task<Error?> ValidateUserAsync(
        Guid userId,
        bool requireMutable,
        CancellationToken ct)
    {
        var user = await userStore.FindByIdAsync(userId, ct);
        if (user is null)
        {
            return IdentityErrors.NotFound();
        }

        if (user.DeletedAt is not null)
        {
            return IdentityErrors.Deleted();
        }

        if (requireMutable && !userPolicy.CanMutate(user.Flags))
        {
            return IdentityErrors.Forbidden(user.Flags);
        }

        return null;
    }

    private static Error? ValidateRole(
        string name,
        string? description)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return IdentityRoleErrors.Validation(
                "name",
                "Role name is required.");
        }

        if (name.Trim().Length > IdentityRoleLimits.MaximumNameLength)
        {
            return IdentityRoleErrors.Validation(
                "name",
                $"Role name cannot exceed {IdentityRoleLimits.MaximumNameLength} characters.");
        }

        if (description?.Trim().Length
            > IdentityRoleLimits.MaximumDescriptionLength)
        {
            return IdentityRoleErrors.Validation(
                "description",
                $"Role description cannot exceed {IdentityRoleLimits.MaximumDescriptionLength} characters.");
        }

        return null;
    }

    private static string? NormalizeDescription(string? description)
        => string.IsNullOrWhiteSpace(description)
            ? null
            : description.Trim();

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult<T> result)
    {
        if (result.IsSuccess)
        {
            op.Success();
        }
        else
        {
            op.Failure(result.Errors.First().Code);
        }

        return result;
    }

    private static OperationResult Finish(
        IIdentityOpScope op,
        OperationResult result)
    {
        if (result.IsSuccess)
        {
            op.Success();
        }
        else
        {
            op.Failure(result.Errors.First().Code);
        }

        return result;
    }
}
