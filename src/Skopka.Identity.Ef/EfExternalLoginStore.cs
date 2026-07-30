using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Users;

namespace Skopka.Identity.Ef;

public sealed class EfExternalLoginStore<TProfile>
    : IExternalLoginStore<TProfile>
{
    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private static readonly Error ExternalLoginNotFoundError = new(
        IdentityErrorCodes.ExternalLoginNotFound,
        "External login is not linked.",
        ErrorType.NotFound);

    private static readonly Error DuplicateExternalLoginError = new(
        IdentityErrorCodes.DuplicateExternalLogin,
        "External login is already linked to another user.",
        ErrorType.Conflict);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    private readonly IdentityDbContext<TProfile> dbContext;
    private readonly IReadOnlyList<IEfIdentityExceptionMapper> exceptionMappers;

    public EfExternalLoginStore(
        IdentityDbContext<TProfile> dbContext,
        IEnumerable<IEfIdentityExceptionMapper> exceptionMappers)
    {
        this.dbContext = dbContext;
        this.exceptionMappers = exceptionMappers.ToArray();
    }

    public async Task<IdentityUser<TProfile>?> FindActiveUserAsync(
        ExternalLoginKey login,
        CancellationToken ct)
    {
        var profile = await dbContext.Profiles
            .AsNoTracking()
            .Include(entity => entity.User)
            .SingleOrDefaultAsync(
                entity => entity.User.DeletedAt == null
                    && entity.User.ExternalLogins.Any(
                        external => external.Provider == login.Provider
                            && external.Subject == login.Subject),
                ct);

        return profile is null
            ? null
            : EfIdentityUserStore<TProfile>.ToModel(profile);
    }

    public async Task<IReadOnlyList<ExternalLoginInfo>> ListAsync(
        Guid userId,
        CancellationToken ct)
        => await dbContext.ExternalLogins
            .AsNoTracking()
            .Where(login => login.UserId == userId)
            .OrderBy(login => login.Provider)
            .ThenBy(login => login.Subject)
            .Select(login => new ExternalLoginInfo(
                login.UserId,
                new ExternalLoginKey(login.Provider, login.Subject),
                login.CreatedAt))
            .ToArrayAsync(ct);

    public Task<OperationResult<IdentityUser<TProfile>>> LinkAsync(
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        string newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct)
        => MutateAsync(
            userId,
            expectedVersion,
            login,
            newSecurityStamp,
            now,
            link: true,
            ct);

    public Task<OperationResult<IdentityUser<TProfile>>> UnlinkAsync(
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        string newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct)
        => MutateAsync(
            userId,
            expectedVersion,
            login,
            newSecurityStamp,
            now,
            link: false,
            ct);

    private async Task<OperationResult<IdentityUser<TProfile>>> MutateAsync(
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        string newSecurityStamp,
        DateTimeOffset now,
        bool link,
        CancellationToken ct)
    {
        var profile = await dbContext.Profiles
            .Include(entity => entity.User)
            .ThenInclude(user => user.ExternalLogins)
            .SingleOrDefaultAsync(entity => entity.UserId == userId, ct);
        if (profile is null)
        {
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                UserNotFoundError);
        }

        var user = profile.User;
        if (user.Version != expectedVersion)
        {
            DetachAggregate(profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                ConcurrencyError);
        }

        var current = user.ExternalLogins.SingleOrDefault(
            external => external.Provider == login.Provider
                && external.Subject == login.Subject);

        if (link)
        {
            if (current is not null)
            {
                return OperationResultFactory.Success(
                    EfIdentityUserStore<TProfile>.ToModel(profile));
            }

            var ownerId = await dbContext.ExternalLogins
                .AsNoTracking()
                .Where(external => external.Provider == login.Provider
                    && external.Subject == login.Subject)
                .Select(external => (Guid?)external.UserId)
                .SingleOrDefaultAsync(ct);
            if (ownerId is not null)
            {
                DetachAggregate(profile);
                return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                    DuplicateExternalLoginError);
            }

            current = new UserExternalLoginEntity
            {
                UserId = user.Id,
                Provider = login.Provider,
                Subject = login.Subject,
                CreatedAt = now,
                User = user
            };
            user.ExternalLogins.Add(current);
            dbContext.ExternalLogins.Add(current);
        }
        else
        {
            if (current is null)
            {
                DetachAggregate(profile);
                return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                    ExternalLoginNotFoundError);
            }

            dbContext.ExternalLogins.Remove(current);
        }

        user.SecurityStamp = newSecurityStamp;
        user.ModifiedAt = now;
        user.Version = checked(expectedVersion + 1);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(
                EfIdentityUserStore<TProfile>.ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            DetachAggregate(profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            DetachAggregate(profile);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
        }
    }

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

    private void DetachAggregate(UserProfileEntity<TProfile> profile)
    {
        foreach (var login in profile.User.ExternalLogins)
        {
            dbContext.Entry(login).State = EntityState.Detached;
        }

        dbContext.Entry(profile.User).State = EntityState.Detached;
        dbContext.Entry(profile).State = EntityState.Detached;
    }
}
