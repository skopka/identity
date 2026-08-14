using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Ef;

public sealed class EfTotpFactorStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : ITotpFactorStore<TProfile>
{
    private static readonly Error ConcurrencyError = new(
        IdentityErrorCodes.ConcurrencyConflict,
        "Concurrency conflict.",
        ErrorType.Conflict);

    private static readonly Error UserNotFoundError = new(
        IdentityErrorCodes.UserNotFound,
        "User not found.",
        ErrorType.NotFound);

    private static readonly Error AlreadyEnabledError = new(
        IdentityErrorCodes.TotpAlreadyEnabled,
        "An authenticator is already enabled.",
        ErrorType.Conflict);

    private static readonly Error EnrollmentInvalidError = new(
        IdentityErrorCodes.TotpEnrollmentInvalid,
        "The authenticator enrollment is invalid or expired.",
        ErrorType.Validation);

    public async Task<StoredTotpFactor?> FindByUserIdAsync(
        Guid userId,
        CancellationToken ct)
    {
        var factor = await dbContext.TotpFactors
            .AsNoTracking()
            .SingleOrDefaultAsync(item => item.UserId == userId, ct);
        if (factor is null)
        {
            return null;
        }

        var remaining = factor.State == TotpFactorState.Enabled
            ? await dbContext.TotpRecoveryCodes
                .AsNoTracking()
                .CountAsync(
                    code => code.UserId == userId
                        && code.EnrollmentId == factor.EnrollmentId
                        && code.UsedAt == null,
                    ct)
            : 0;
        return Map(factor, remaining);
    }

    public async Task<OperationResult> CreateOrReplacePendingAsync(
        NewTotpEnrollment enrollment,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (!await dbContext.Users.AnyAsync(
                user => user.Id == enrollment.UserId,
                ct))
        {
            return OperationResultFactory.Fail(UserNotFoundError);
        }

        var factor = await dbContext.TotpFactors
            .SingleOrDefaultAsync(
                item => item.UserId == enrollment.UserId,
                ct);
        if (factor?.State == TotpFactorState.Enabled)
        {
            Detach(factor);
            return OperationResultFactory.Fail(AlreadyEnabledError);
        }

        if (factor is null)
        {
            dbContext.TotpFactors.Add(
                new TotpFactorEntity
                {
                    UserId = enrollment.UserId,
                    EnrollmentId = enrollment.EnrollmentId,
                    ProtectedSecret = enrollment.ProtectedSecret,
                    State = TotpFactorState.Pending,
                    Version = 1,
                    PendingExpiresAt = Normalize(enrollment.ExpiresAt),
                    CreatedAt = Normalize(now),
                    ModifiedAt = Normalize(now),
                });
        }
        else
        {
            factor.EnrollmentId = enrollment.EnrollmentId;
            factor.ProtectedSecret = enrollment.ProtectedSecret;
            factor.State = TotpFactorState.Pending;
            factor.LastAcceptedCounter = null;
            factor.PendingExpiresAt = Normalize(enrollment.ExpiresAt);
            factor.EnabledAt = null;
            factor.ModifiedAt = Normalize(now);
            factor.Version = checked(factor.Version + 1);
        }

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(factor);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    public async Task<OperationResult<StoredTotpFactor>> EnableAsync(
        Guid userId,
        Guid enrollmentId,
        long expectedVersion,
        long initialAcceptedCounter,
        IReadOnlyCollection<string> recoveryCodeHashes,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var factor = await dbContext.TotpFactors
            .SingleOrDefaultAsync(item => item.UserId == userId, ct);
        if (factor is null
            || factor.State != TotpFactorState.Pending
            || factor.EnrollmentId != enrollmentId
            || factor.PendingExpiresAt is null
            || factor.PendingExpiresAt <= now)
        {
            Detach(factor);
            return OperationResultFactory.Fail<StoredTotpFactor>(
                EnrollmentInvalidError);
        }

        if (factor.Version != expectedVersion)
        {
            Detach(factor);
            return OperationResultFactory.Fail<StoredTotpFactor>(
                ConcurrencyError);
        }

        factor.State = TotpFactorState.Enabled;
        factor.LastAcceptedCounter = initialAcceptedCounter;
        factor.PendingExpiresAt = null;
        factor.EnabledAt = Normalize(now);
        factor.ModifiedAt = Normalize(now);
        factor.Version = checked(factor.Version + 1);
        foreach (var hash in recoveryCodeHashes)
        {
            dbContext.TotpRecoveryCodes.Add(
                new TotpRecoveryCodeEntity
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    EnrollmentId = enrollmentId,
                    CodeHash = hash,
                    Version = 1,
                    CreatedAt = Normalize(now),
                });
        }

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(
                Map(factor, recoveryCodeHashes.Count));
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(factor);
            return OperationResultFactory.Fail<StoredTotpFactor>(
                ConcurrencyError);
        }
    }

    public async Task<OperationResult> DisableAsync(
        Guid userId,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var factor = await dbContext.TotpFactors
            .SingleOrDefaultAsync(item => item.UserId == userId, ct);
        if (factor is null)
        {
            return OperationResultFactory.Success();
        }

        dbContext.TotpFactors.Remove(factor);
        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success();
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(factor);
            return OperationResultFactory.Fail(ConcurrencyError);
        }
    }

    public async Task<OperationResult<bool>> TryAcceptCounterAsync(
        Guid userId,
        Guid enrollmentId,
        long expectedVersion,
        long counter,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var factor = await dbContext.TotpFactors
            .SingleOrDefaultAsync(item => item.UserId == userId, ct);
        if (factor is null
            || factor.State != TotpFactorState.Enabled
            || factor.EnrollmentId != enrollmentId
            || factor.LastAcceptedCounter >= counter)
        {
            Detach(factor);
            return OperationResultFactory.Success(false);
        }

        if (factor.Version != expectedVersion)
        {
            Detach(factor);
            return OperationResultFactory.Fail<bool>(ConcurrencyError);
        }

        factor.LastAcceptedCounter = counter;
        factor.ModifiedAt = Normalize(now);
        factor.Version = checked(factor.Version + 1);
        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(true);
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(factor);
            return OperationResultFactory.Fail<bool>(ConcurrencyError);
        }
    }

    public async Task<OperationResult<bool>> TryConsumeRecoveryCodeAsync(
        Guid userId,
        Guid enrollmentId,
        string recoveryCodeHash,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var code = await dbContext.TotpRecoveryCodes
            .SingleOrDefaultAsync(
                item => item.UserId == userId
                    && item.EnrollmentId == enrollmentId
                    && item.CodeHash == recoveryCodeHash
                    && item.UsedAt == null,
                ct);
        if (code is null)
        {
            return OperationResultFactory.Success(false);
        }

        code.UsedAt = Normalize(now);
        code.Version = checked(code.Version + 1);
        try
        {
            await dbContext.SaveChangesAsync(ct);
            return OperationResultFactory.Success(true);
        }
        catch (DbUpdateConcurrencyException)
        {
            Detach(code);
            return OperationResultFactory.Success(false);
        }
    }

    private static StoredTotpFactor Map(
        TotpFactorEntity factor,
        int recoveryCodesRemaining)
        => new(
            factor.UserId,
            factor.EnrollmentId,
            factor.ProtectedSecret,
            factor.State,
            factor.LastAcceptedCounter,
            recoveryCodesRemaining,
            factor.Version,
            factor.PendingExpiresAt,
            factor.EnabledAt,
            factor.CreatedAt,
            factor.ModifiedAt);

    private static DateTimeOffset Normalize(DateTimeOffset value)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Ticks - utc.Ticks % ticksPerMicrosecond,
            TimeSpan.Zero);
    }

    private void Detach(object? entity)
    {
        if (entity is not null)
        {
            dbContext.Entry(entity).State = EntityState.Detached;
        }
    }
}
