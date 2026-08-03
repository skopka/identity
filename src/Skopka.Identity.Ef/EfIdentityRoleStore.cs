using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Roles;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityRoleStore<TProfile>
    : IIdentityRoleStore<TProfile>
{
    private static readonly Error RoleNotFoundError = new(
        IdentityErrorCodes.RoleNotFound,
        "Role not found.",
        ErrorType.NotFound);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    private readonly IdentityDbContext<TProfile> dbContext;
    private readonly IReadOnlyList<IEfIdentityExceptionMapper> exceptionMappers;

    public EfIdentityRoleStore(IdentityDbContext<TProfile> dbContext)
        : this(dbContext, [])
    {
    }

    public EfIdentityRoleStore(
        IdentityDbContext<TProfile> dbContext,
        IEnumerable<IEfIdentityExceptionMapper> exceptionMappers)
    {
        this.dbContext = dbContext;
        this.exceptionMappers = exceptionMappers.ToArray();
    }

    public async Task<IdentityRole?> FindByIdAsync(
        Guid roleId,
        CancellationToken ct)
    {
        var role = await dbContext.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, ct);

        return role is null ? null : ToModel(role);
    }

    public async Task<IdentityRole?> FindByNormalizedNameAsync(
        string normalizedName,
        CancellationToken ct)
    {
        var role = await dbContext.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.NormalizedName == normalizedName,
                ct);

        return role is null ? null : ToModel(role);
    }

    public async Task<OperationResult<IdentityRole>> CreateAsync(
        NewIdentityRole role,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = new RoleEntity
        {
            Id = Guid.NewGuid(),
            Name = role.Name,
            NormalizedName = role.NormalizedName,
            Description = role.Description,
            ParentId = role.ParentId,
            Version = 1,
            CreatedAt = now,
            ModifiedAt = now
        };

        dbContext.Roles.Add(entity);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(entity));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Fail<IdentityRole>(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(entity);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityRole>(error);
        }
    }

    public async Task<OperationResult<IdentityRole>> UpdateAsync(
        Guid roleId,
        long expectedVersion,
        UpdatedIdentityRole role,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var entity = await dbContext.Roles
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, ct);
        if (entity is null)
        {
            return OperationResultFactory.Fail<IdentityRole>(RoleNotFoundError);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail<IdentityRole>(ConcurrencyError);
        }

        entity.Name = role.Name;
        entity.NormalizedName = role.NormalizedName;
        entity.Description = role.Description;
        entity.ParentId = role.ParentId;
        entity.Version = checked(expectedVersion + 1);
        entity.ModifiedAt = now;

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(entity));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Fail<IdentityRole>(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(entity);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityRole>(error);
        }
    }

    public async Task<OperationResult> DeleteAsync(
        Guid roleId,
        long expectedVersion,
        CancellationToken ct)
    {
        var entity = await dbContext.Roles
            .SingleOrDefaultAsync(candidate => candidate.Id == roleId, ct);
        if (entity is null)
        {
            return OperationResultFactory.Fail(RoleNotFoundError);
        }

        if (entity.Version != expectedVersion)
        {
            Detach(entity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }

        dbContext.Roles.Remove(entity);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(entity);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    internal static IdentityRole ToModel(RoleEntity role)
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
