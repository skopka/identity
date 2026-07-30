using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityUserStore<TProfile>
    : IIdentityUserStore<TProfile>,
      IIdentityUserLookupStore<TProfile>
{
    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    private readonly IdentityDbContext<TProfile> dbContext;
    private readonly IReadOnlyList<IEfIdentityExceptionMapper> exceptionMappers;

    public EfIdentityUserStore(IdentityDbContext<TProfile> dbContext)
        : this(dbContext, [])
    {
    }

    public EfIdentityUserStore(
        IdentityDbContext<TProfile> dbContext,
        IEnumerable<IEfIdentityExceptionMapper> exceptionMappers)
    {
        this.dbContext = dbContext;
        this.exceptionMappers = exceptionMappers.ToArray();
    }

    public async Task<IdentityUser<TProfile>?> FindByIdAsync(Guid id, CancellationToken ct)
    {
        var profile = await dbContext.Profiles
            .AsNoTracking()
            .Include(entity => entity.User)
            .SingleOrDefaultAsync(entity => entity.UserId == id, ct);

        return profile is null ? null : ToModel(profile);
    }

    public async Task<IdentityUser<TProfile>?> FindActiveByNormalizedUserNameAsync(
        string normalizedUserName,
        CancellationToken ct)
    {
        var profile = await dbContext.Profiles
            .AsNoTracking()
            .Include(entity => entity.User)
            .SingleOrDefaultAsync(
                entity => entity.User.DeletedAt == null
                    && entity.User.NormalizedUserName == normalizedUserName,
                ct);

        return profile is null ? null : ToModel(profile);
    }

    public async Task<IdentityUser<TProfile>?> FindActiveByNormalizedEmailAsync(
        string normalizedEmail,
        CancellationToken ct)
    {
        var profile = await dbContext.Profiles
            .AsNoTracking()
            .Include(entity => entity.User)
            .SingleOrDefaultAsync(
                entity => entity.User.DeletedAt == null
                    && entity.User.NormalizedEmail == normalizedEmail,
                ct);

        return profile is null ? null : ToModel(profile);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> CreateAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var profile = new UserProfileEntity<TProfile>
        {
            UserId = user.Id ?? Guid.NewGuid(),
            UserName = user.UserName,
            Email = user.Email,
            Phone = user.Phone,
            Profile = user.Profile
        };

        var authUser = new AuthUserEntity
        {
            Id = profile.UserId,
            Flags = (int)user.Flags,
            NormalizedUserName = handles.UserName,
            NormalizedEmail = handles.Email,
            NormalizedPhone = handles.Phone,
            Version = 1,
            SecurityStamp = user.SecurityStamp,
            CreatedAt = now,
            ModifiedAt = now,
            Profile = profile
        };

        profile.User = authUser;
        dbContext.Users.Add(authUser);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(authUser, profile);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
        }
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> UpdateHandlesAsync(
        Guid userId,
        long expectedVersion,
        UpdatedHandles updated,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var profile = await FindTrackedProfileAsync(userId, ct);
        if (profile is null)
        {
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(UserNotFoundError);
        }

        var authUser = profile.User;
        if (authUser.Version != expectedVersion)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }

        profile.UserName = updated.UserName;
        profile.Email = updated.Email;
        profile.Phone = updated.Phone;

        authUser.NormalizedUserName = updated.NormalizedUserName;
        authUser.NormalizedEmail = updated.NormalizedEmail;
        authUser.NormalizedPhone = updated.NormalizedPhone;
        authUser.EmailConfirmed = updated.EmailConfirmed;
        authUser.PhoneConfirmed = updated.PhoneConfirmed;
        BumpVersion(authUser, expectedVersion, now);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(authUser, profile);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
        }
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> UpdateProfileAsync(
        Guid userId,
        long expectedVersion,
        TProfile profileValue,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var profile = await FindTrackedProfileAsync(userId, ct);
        if (profile is null)
        {
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(UserNotFoundError);
        }

        var authUser = profile.User;
        if (authUser.Version != expectedVersion)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }

        profile.Profile = profileValue;
        BumpVersion(authUser, expectedVersion, now);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(authUser, profile);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
        }
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> UpdateSecurityStampAsync(
        Guid userId,
        long expectedVersion,
        string securityStamp,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var profile = await FindTrackedProfileAsync(userId, ct);
        if (profile is null)
        {
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(UserNotFoundError);
        }

        var authUser = profile.User;
        if (authUser.Version != expectedVersion)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }

        authUser.SecurityStamp = securityStamp;
        BumpVersion(authUser, expectedVersion, now);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser, profile);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(ConcurrencyError);
        }
    }

    public async Task<OperationResult> UpdateStateAsync(
        Guid userId,
        long expectedVersion,
        DateTimeOffset? deletedAt,
        DateTimeOffset? blockedAt,
        DateTimeOffset? blockedUntil,
        string? newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var authUser = await dbContext.Users.SingleOrDefaultAsync(user => user.Id == userId, ct);
        if (authUser is null)
        {
            return OperationResultFactory.Fail(UserNotFoundError);
        }

        if (authUser.Version != expectedVersion)
        {
            Detach(authUser);
            return OperationResultFactory.Fail(ConcurrencyError);
        }

        authUser.DeletedAt = deletedAt;
        authUser.BlockedAt = blockedAt;
        authUser.BlockedUntil = blockedUntil;
        if (newSecurityStamp is not null)
        {
            authUser.SecurityStamp = newSecurityStamp;
        }

        BumpVersion(authUser, expectedVersion, now);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(authUser);
            var error = MapException(exception);
            if (error is null)
            {
                throw;
            }

            return OperationResultFactory.Fail(error);
        }
    }

    private Task<UserProfileEntity<TProfile>?> FindTrackedProfileAsync(Guid userId, CancellationToken ct)
        => dbContext.Profiles
            .Include(profile => profile.User)
            .SingleOrDefaultAsync(profile => profile.UserId == userId, ct);

    private static void BumpVersion(AuthUserEntity user, long expectedVersion, DateTimeOffset now)
    {
        user.Version = checked(expectedVersion + 1);
        user.ModifiedAt = now;
    }

    internal static IdentityUser<TProfile> ToModel(UserProfileEntity<TProfile> profile)
    {
        var user = profile.User;

        return new IdentityUser<TProfile>(
            user.Id,
            (UserFlags)user.Flags,
            profile.UserName,
            profile.Email,
            user.EmailConfirmed,
            profile.Phone,
            user.PhoneConfirmed,
            profile.Profile,
            user.Version,
            user.SecurityStamp,
            user.DeletedAt,
            user.BlockedAt,
            user.BlockedUntil,
            user.CreatedAt,
            user.ModifiedAt);
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

    private void Detach(params object[] entities)
    {
        foreach (var entity in entities)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
