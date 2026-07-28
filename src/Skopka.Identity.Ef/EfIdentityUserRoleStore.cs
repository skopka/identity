using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Roles;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityUserRoleStore<TProfile>
    : IIdentityUserRoleStore<TProfile>
{
    private static readonly Error AlreadyAssignedError = new(
        IdentityErrorCodes.RoleAlreadyAssigned,
        "Role is already assigned to the user.",
        ErrorType.Conflict);

    private readonly IdentityDbContext<TProfile> dbContext;
    private readonly IReadOnlyList<IEfIdentityExceptionMapper> exceptionMappers;

    public EfIdentityUserRoleStore(IdentityDbContext<TProfile> dbContext)
        : this(dbContext, [])
    {
    }

    public EfIdentityUserRoleStore(
        IdentityDbContext<TProfile> dbContext,
        IEnumerable<IEfIdentityExceptionMapper> exceptionMappers)
    {
        this.dbContext = dbContext;
        this.exceptionMappers = exceptionMappers.ToArray();
    }

    public async Task<IReadOnlyList<IdentityRole>> GetRolesAsync(
        Guid userId,
        CancellationToken ct)
    {
        var roles = await dbContext.UserRoles
            .AsNoTracking()
            .Where(membership => membership.UserId == userId)
            .Select(membership => membership.Role)
            .OrderBy(role => role.NormalizedName)
            .ToListAsync(ct);

        return roles.Select(ToModel).ToArray();
    }

    public Task<bool> IsInRoleAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct)
        => dbContext.UserRoles
            .AsNoTracking()
            .AnyAsync(
                membership => membership.UserId == userId
                    && membership.RoleId == roleId,
                ct);

    public async Task<OperationResult> AddAsync(
        Guid userId,
        Guid roleId,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var exists = await dbContext.UserRoles
            .AsNoTracking()
            .AnyAsync(
                membership => membership.UserId == userId
                    && membership.RoleId == roleId,
                ct);
        if (exists)
        {
            return OperationResultFactory.Fail(AlreadyAssignedError);
        }

        var entity = new UserRoleEntity
        {
            UserId = userId,
            RoleId = roleId,
            CreatedAt = now
        };
        dbContext.UserRoles.Add(entity);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateException exception)
        {
            Detach(entity);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail(error);
        }
    }

    public async Task<OperationResult> RemoveAsync(
        Guid userId,
        Guid roleId,
        CancellationToken ct)
    {
        var entity = await dbContext.UserRoles.SingleOrDefaultAsync(
            membership => membership.UserId == userId
                && membership.RoleId == roleId,
            ct);
        if (entity is null)
        {
            return OperationResultFactory.Success();
        }

        dbContext.UserRoles.Remove(entity);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Success();
        }
    }

    private static IdentityRole ToModel(RoleEntity role)
        => new(
            role.Id,
            role.Name,
            role.Description,
            role.ParentId,
            role.Version,
            role.CreatedAt,
            role.ModifiedAt);

    private Error? MapException(DbUpdateException exception)
    {
        foreach (var mapper in exceptionMappers)
        {
            if (mapper.TryMap(exception, out var error))
            {
                return error;
            }
        }

        return null;
    }

    private void Detach(params object[] entities)
    {
        foreach (var entity in entities)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
