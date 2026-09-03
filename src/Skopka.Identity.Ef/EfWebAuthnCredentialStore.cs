using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.WebAuthn;

namespace Skopka.Identity.Ef;

public sealed class EfWebAuthnCredentialStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IWebAuthnCredentialStore<TProfile>
{
    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private static readonly Error AlreadyRegisteredError = new(
        IdentityErrorCodes.WebAuthnCredentialAlreadyRegistered,
        "The credential is already registered.",
        ErrorType.Conflict);

    private static readonly Error NotFoundError = new(
        IdentityErrorCodes.WebAuthnCredentialNotFound,
        "The credential was not found.",
        ErrorType.NotFound);

    public async Task<StoredWebAuthnCredential?> FindByCredentialIdAsync(
        byte[] credentialId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        if (credentialId.Length is < WebAuthnLimits.MinimumCredentialIdLength
            or > WebAuthnLimits.MaximumCredentialIdLength)
        {
            return null;
        }

        var credential = await dbContext.WebAuthnCredentials
            .AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.CredentialId == credentialId,
                ct);
        return credential is null ? null : Map(credential);
    }

    public async Task<IReadOnlyList<StoredWebAuthnCredential>> ListByUserIdAsync(
        Guid userId,
        CancellationToken ct)
    {
        var credentials = await dbContext.WebAuthnCredentials
            .AsNoTracking()
            .Where(item => item.UserId == userId)
            .OrderBy(item => item.CreatedAt)
            .ThenBy(item => item.Id)
            .ToListAsync(ct);
        return [.. credentials.Select(Map)];
    }

    public async Task<OperationResult> CreateAsync(
        NewWebAuthnCredential credential,
        DateTimeOffset now,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (!await dbContext.Users.AnyAsync(user => user.Id == credential.UserId, ct))
        {
            return OperationResultFactory.Fail(UserNotFoundError);
        }

        // Checked before the insert for a plain answer, and again by the unique
        // index for the real one: two registrations of one authenticator can
        // arrive at the same moment.
        if (await dbContext.WebAuthnCredentials.AnyAsync(
                item => item.CredentialId == credential.CredentialId,
                ct))
        {
            return OperationResultFactory.Fail(AlreadyRegisteredError);
        }

        dbContext.WebAuthnCredentials.Add(new WebAuthnCredentialEntity
        {
            Id = credential.Id,
            UserId = credential.UserId,
            CredentialId = credential.CredentialId,
            PublicKey = credential.PublicKey,
            Algorithm = credential.Algorithm,
            SignatureCounter = credential.SignatureCounter,
            AuthenticatorId = credential.AuthenticatorId,
            BackedUp = credential.BackedUp,
            Label = credential.Label,
            Version = 1,
            CreatedAt = now,
        });
        try
        {
            await dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return OperationResultFactory.Fail(AlreadyRegisteredError);
        }

        return OperationResultFactory.Success();
    }

    public async Task<OperationResult<bool>> TryAdvanceCounterAsync(
        Guid id,
        long expectedVersion,
        long counter,
        DateTimeOffset usedAt,
        CancellationToken ct)
    {
        var credential = await dbContext.WebAuthnCredentials
            .SingleOrDefaultAsync(item => item.Id == id, ct);
        if (credential is null)
        {
            return OperationResultFactory.Fail<bool>(NotFoundError);
        }

        if (credential.Version != expectedVersion)
        {
            // The same assertion arriving twice at once, which is the one case
            // this answers "no" to rather than failing: the caller has already
            // decided the signature is good and only wanted to record it.
            dbContext.ChangeTracker.Clear();
            return OperationResultFactory.Success(false);
        }

        credential.SignatureCounter = counter;
        credential.LastUsedAt = usedAt;
        credential.Version = expectedVersion + 1;
        try
        {
            await dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            dbContext.ChangeTracker.Clear();
            return OperationResultFactory.Success(false);
        }

        return OperationResultFactory.Success(true);
    }

    public async Task<OperationResult> RemoveAsync(
        Guid userId,
        Guid id,
        CancellationToken ct)
    {
        // Both, so that a credential id learned elsewhere cannot be used to
        // unregister someone else's key.
        var credential = await dbContext.WebAuthnCredentials
            .SingleOrDefaultAsync(
                item => item.Id == id && item.UserId == userId,
                ct);
        if (credential is null)
        {
            return OperationResultFactory.Fail(NotFoundError);
        }

        dbContext.WebAuthnCredentials.Remove(credential);
        await dbContext.SaveChangesAsync(ct);
        return OperationResultFactory.Success();
    }

    private static StoredWebAuthnCredential Map(WebAuthnCredentialEntity credential)
        => new(
            credential.Id,
            credential.UserId,
            credential.CredentialId,
            credential.PublicKey,
            credential.Algorithm,
            credential.SignatureCounter,
            credential.AuthenticatorId,
            credential.BackedUp,
            credential.Label,
            credential.Version,
            credential.CreatedAt,
            credential.LastUsedAt);
}
