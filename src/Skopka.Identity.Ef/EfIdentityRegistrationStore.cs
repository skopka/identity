using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Registration;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityRegistrationStore<TProfile>
    : IIdentityRegistrationStore<TProfile>
{
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

    public EfIdentityRegistrationStore(
        IdentityDbContext<TProfile> dbContext,
        IEnumerable<IEfIdentityExceptionMapper> exceptionMappers)
    {
        this.dbContext = dbContext;
        this.exceptionMappers = exceptionMappers.ToArray();
    }

    public Task<OperationResult<IdentityUser<TProfile>>> CreateWithPasswordAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        string passwordVerifier,
        DateTimeOffset now,
        CancellationToken ct)
        => CreateAsync(
            user,
            handles,
            passwordVerifier,
            externalLogin: null,
            now,
            ct);

    public async Task<OperationResult<IdentityUser<TProfile>>>
        CreateWithExternalLoginAsync(
            NewIdentityUser<TProfile> user,
            NormalizedHandles handles,
            ExternalLoginKey login,
            DateTimeOffset now,
            CancellationToken ct)
    {
        var loginExists = await dbContext.ExternalLogins
            .AsNoTracking()
            .AnyAsync(
                external => external.Provider == login.Provider
                    && external.Subject == login.Subject,
                ct);
        if (loginExists)
        {
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                DuplicateExternalLoginError);
        }

        return await CreateAsync(
            user,
            handles,
            passwordVerifier: null,
            login,
            now,
            ct);
    }

    private async Task<OperationResult<IdentityUser<TProfile>>> CreateAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        string? passwordVerifier,
        ExternalLoginKey? externalLogin,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var userId = user.Id ?? Guid.NewGuid();
        var profile = new UserProfileEntity<TProfile>
        {
            UserId = userId,
            UserName = user.UserName,
            Email = user.Email,
            Phone = user.Phone,
            Profile = user.Profile
        };
        var authUser = new AuthUserEntity
        {
            Id = userId,
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

        var loginIdentifiers = (handles.LoginIdentifierKeys
                ?? DistinctKeys(handles.UserName, handles.Email, handles.Phone))
            .Where(normalizedKey => !string.IsNullOrEmpty(normalizedKey))
            .Distinct(StringComparer.Ordinal)
            .Select(normalizedKey => new LoginIdentifierEntity
            {
                UserId = userId,
                NormalizedKey = normalizedKey,
                IsActive = true,
                User = authUser
            })
            .ToArray();
        foreach (var identifier in loginIdentifiers)
        {
            authUser.LoginIdentifiers.Add(identifier);
        }

        UserCredentialEntity? credential = null;
        if (passwordVerifier is not null)
        {
            credential = new UserCredentialEntity
            {
                UserId = userId,
                PasswordVerifier = passwordVerifier,
                UpdatedAt = now,
                User = authUser
            };
            authUser.Credential = credential;
        }

        UserExternalLoginEntity? login = null;
        if (externalLogin is not null)
        {
            login = new UserExternalLoginEntity
            {
                UserId = userId,
                Provider = externalLogin.Provider,
                Subject = externalLogin.Subject,
                CreatedAt = now,
                User = authUser
            };
            authUser.ExternalLogins.Add(login);
        }

        dbContext.Users.Add(authUser);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(
                EfIdentityUserStore<TProfile>.ToModel(profile));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(authUser, profile, credential, login, loginIdentifiers);
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(
                ConcurrencyError);
        }
        catch (DbUpdateException exception)
        {
            Detach(authUser, profile, credential, login, loginIdentifiers);
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

    private static string[] DistinctKeys(params string?[] keys)
        => keys
            .Where(key => !string.IsNullOrEmpty(key))
            .Select(key => key!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private void Detach(params object?[] entities)
    {
        foreach (var entity in entities)
        {
            if (entity is IEnumerable<LoginIdentifierEntity> identifiers)
            {
                foreach (var identifier in identifiers)
                {
                    dbContext.Entry(identifier).State = EntityState.Detached;
                }
            }
            else if (entity is not null)
            {
                dbContext.Entry(entity).State = EntityState.Detached;
            }
        }
    }
}
