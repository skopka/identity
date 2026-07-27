using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Ef;

public sealed class EfPasswordCredentialStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IPasswordCredentialStore<TProfile>
{
    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    public Task<string?> FindPasswordVerifierAsync(
        Guid userId,
        CancellationToken ct)
        => dbContext.Credentials
            .AsNoTracking()
            .Where(credential => credential.UserId == userId)
            .Select(credential => credential.PasswordVerifier)
            .SingleOrDefaultAsync(ct);

    public async Task<OperationResult> ReplacePasswordVerifierAsync(
        Guid userId,
        long expectedVersion,
        string? expectedPasswordVerifier,
        string? passwordVerifier,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var user = await dbContext.Users
            .Include(entity => entity.Credential)
            .SingleOrDefaultAsync(entity => entity.Id == userId, ct);

        if (user is null)
        {
            return OperationResultFactory.Fail(UserNotFoundError);
        }

        if (user.Version != expectedVersion
            || !string.Equals(
                user.Credential?.PasswordVerifier,
                expectedPasswordVerifier,
                StringComparison.Ordinal))
        {
            Detach(user, user.Credential);
            return OperationResultFactory.Fail(ConcurrencyError);
        }

        var credentialWasAdded = false;
        if (user.Credential is null && passwordVerifier is not null)
        {
            var credential = new UserCredentialEntity
            {
                UserId = user.Id,
                PasswordVerifier = passwordVerifier,
                UpdatedAt = now,
                User = user
            };

            user.Credential = credential;
            dbContext.Credentials.Add(credential);
            credentialWasAdded = true;
        }
        else if (user.Credential is not null)
        {
            user.Credential.PasswordVerifier = passwordVerifier;
            user.Credential.UpdatedAt = now;
        }

        user.Version = checked(expectedVersion + 1);
        user.ModifiedAt = now;

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(user, user.Credential);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
        catch (DbUpdateException) when (credentialWasAdded)
        {
            Detach(user, user.Credential);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    private void Detach(params object?[] entities)
    {
        foreach (var entity in entities)
        {
            if (entity is not null)
            {
                dbContext.Entry(entity).State = EntityState.Detached;
            }
        }
    }
}
