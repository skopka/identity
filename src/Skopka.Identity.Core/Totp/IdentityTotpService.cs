using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Users;

namespace Skopka.Identity.Totp;

public sealed class IdentityTotpService<TProfile>(
    ITotpFactorStore<TProfile> factorStore,
    IIdentityUserStore<TProfile> userStore,
    ITotpCodeProvider codeProvider,
    ITotpSecretProtector secretProtector,
    TotpOptions options,
    IdentityRateLimitOptions rateLimitOptions,
    IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters,
    IIdentityMetrics metrics)
    : IIdentityTotpService<TProfile>
{
    private readonly IIdentityRateLimiter<TProfile>? rateLimiter =
        rateLimiters.FirstOrDefault();

    public async Task<OperationResult<TotpFactorStatus>> GetStatusAsync(
        Guid userId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("totp.status");
        if (userId == Guid.Empty)
        {
            return Fail<TotpFactorStatus>(
                op,
                Validation("userId", "UserId is required."));
        }

        var user = await userStore.FindByIdAsync(userId, ct);
        var userError = ValidateActiveUser(user, DateTimeOffset.UtcNow);
        if (userError is not null)
        {
            return Fail<TotpFactorStatus>(op, userError);
        }

        var factor = await factorStore.FindByUserIdAsync(userId, ct);
        op.Success();
        return OperationResultFactory.Success(ToStatus(userId, factor));
    }

    public async Task<OperationResult<TotpEnrollment>> BeginEnrollmentAsync(
        BeginTotpEnrollmentCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("totp.enrollment.begin");
        ArgumentNullException.ThrowIfNull(command);
        var validation = ValidateRequest(command.UserId, command.ClientKey);
        if (validation is not null)
        {
            return Fail<TotpEnrollment>(op, validation);
        }

        var now = DateTimeOffset.UtcNow;
        var limited = await CheckStartRateLimitsAsync(
            command.UserId,
            command.ClientKey,
            ct);
        if (limited is not null)
        {
            return Fail<TotpEnrollment>(op, limited);
        }

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<TotpEnrollment>(op, userError);
        }

        var current = await factorStore.FindByUserIdAsync(command.UserId, ct);
        if (current?.State == TotpFactorState.Enabled)
        {
            return Fail<TotpEnrollment>(op, TotpErrors.AlreadyEnabled());
        }

        var secret = codeProvider.CreateSecret();
        var protectedSecret = secretProtector.Protect(secret);
        if (string.IsNullOrWhiteSpace(protectedSecret)
            || protectedSecret.Length > TotpLimits.MaximumProtectedSecretLength)
        {
            throw new InvalidOperationException(
                "The TOTP secret protector produced an invalid payload.");
        }

        var enrollment = new NewTotpEnrollment(
            command.UserId,
            Guid.NewGuid(),
            protectedSecret,
            now.Add(options.EnrollmentLifetime));
        var stored = await factorStore.CreateOrReplacePendingAsync(
            enrollment,
            now,
            ct);
        if (!stored.IsSuccess)
        {
            return Finish<TotpEnrollment>(op, stored);
        }

        op.Success();
        return OperationResultFactory.Success(
            new TotpEnrollment(
                enrollment.EnrollmentId,
                secret,
                enrollment.ExpiresAt));
    }

    public async Task<OperationResult<ConfirmedTotpEnrollment>>
        ConfirmEnrollmentAsync(
            ConfirmTotpEnrollmentCommand command,
            CancellationToken ct)
    {
        using var op = metrics.Begin("totp.enrollment.confirm");
        ArgumentNullException.ThrowIfNull(command);
        var validation = ValidateRequest(command.UserId, command.ClientKey);
        if (validation is null
            && (command.EnrollmentId == Guid.Empty
                || string.IsNullOrWhiteSpace(command.Code)
                || command.Code.Length > TotpLimits.MaximumResponseLength))
        {
            validation = TotpErrors.EnrollmentInvalid();
        }

        if (validation is not null)
        {
            return Fail<ConfirmedTotpEnrollment>(op, validation);
        }

        var now = DateTimeOffset.UtcNow;
        var limited = await CheckResponseRateLimitsAsync(
            command.UserId,
            command.ClientKey,
            ct);
        if (limited is not null)
        {
            return Fail<ConfirmedTotpEnrollment>(op, limited);
        }

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<ConfirmedTotpEnrollment>(op, userError);
        }

        var factor = await factorStore.FindByUserIdAsync(command.UserId, ct);
        if (factor is null
            || factor.State != TotpFactorState.Pending
            || factor.EnrollmentId != command.EnrollmentId
            || factor.PendingExpiresAt is null
            || factor.PendingExpiresAt <= now)
        {
            return Fail<ConfirmedTotpEnrollment>(
                op,
                TotpErrors.EnrollmentInvalid());
        }

        if (!secretProtector.TryUnprotect(
                factor.ProtectedSecret,
                out var secret))
        {
            return Fail<ConfirmedTotpEnrollment>(
                op,
                TotpErrors.SecretUnavailable());
        }

        if (!codeProvider.TryMatchCounter(
                secret,
                command.Code,
                now,
                minimumExclusiveCounter: null,
                out var acceptedCounter))
        {
            return Fail<ConfirmedTotpEnrollment>(
                op,
                TotpErrors.CodeInvalid());
        }

        var recoveryCodes = Enumerable.Range(0, options.RecoveryCodeCount)
            .Select(_ => TotpRecoveryCodes.Create())
            .ToArray();
        var recoveryHashes = recoveryCodes
            .Select(TotpRecoveryCodes.Hash)
            .ToArray();
        var enabled = await factorStore.EnableAsync(
            factor.UserId,
            factor.EnrollmentId,
            factor.Version,
            acceptedCounter,
            recoveryHashes,
            now,
            ct);
        if (!enabled.IsSuccess)
        {
            return Finish<ConfirmedTotpEnrollment>(op, enabled);
        }

        op.Success();
        return OperationResultFactory.Success(
            new ConfirmedTotpEnrollment(
                ToStatus(command.UserId, enabled.Value),
                recoveryCodes));
    }

    public async Task<OperationResult> DisableAsync(
        Guid userId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("totp.disable");
        if (userId == Guid.Empty)
        {
            return Fail(op, Validation("userId", "UserId is required."));
        }

        var result = await factorStore.DisableAsync(
            userId,
            DateTimeOffset.UtcNow,
            ct);
        return Finish(op, result);
    }

    private async Task<Error?> CheckStartRateLimitsAsync(
        Guid userId,
        string? clientKey,
        CancellationToken ct)
    {
        if (rateLimiter is null)
        {
            return null;
        }

        var normalizedClient = NormalizeClientKey(clientKey);
        if (normalizedClient is not null)
        {
            var client = await rateLimiter.HitAsync(
                new RateLimitRequest(
                    "totp.enrollment.client",
                    normalizedClient,
                    rateLimitOptions.VerificationClientPermitLimit,
                    rateLimitOptions.VerificationClientWindow),
                ct);
            if (!client.IsAllowed)
            {
                return IdentityRateLimitErrors.Exceeded(client.RetryAfter);
            }
        }

        var account = await rateLimiter.HitAsync(
            new RateLimitRequest(
                "totp.enrollment.account",
                userId.ToString("N"),
                rateLimitOptions.VerificationAccountPermitLimit,
                rateLimitOptions.VerificationAccountWindow),
            ct);
        return account.IsAllowed
            ? null
            : IdentityRateLimitErrors.Exceeded(account.RetryAfter);
    }

    private async Task<Error?> CheckResponseRateLimitsAsync(
        Guid userId,
        string? clientKey,
        CancellationToken ct)
    {
        if (rateLimiter is null)
        {
            return null;
        }

        var normalizedClient = NormalizeClientKey(clientKey);
        if (normalizedClient is not null)
        {
            var client = await rateLimiter.HitAsync(
                new RateLimitRequest(
                    "verification.response.client",
                    normalizedClient,
                    rateLimitOptions.VerificationResponseClientPermitLimit,
                    rateLimitOptions.VerificationResponseClientWindow),
                ct);
            if (!client.IsAllowed)
            {
                return IdentityRateLimitErrors.Exceeded(client.RetryAfter);
            }
        }

        var account = await rateLimiter.HitAsync(
            new RateLimitRequest(
                "verification.response.account",
                userId.ToString("N"),
                rateLimitOptions.VerificationResponseAccountPermitLimit,
                rateLimitOptions.VerificationResponseAccountWindow),
            ct);
        return account.IsAllowed
            ? null
            : IdentityRateLimitErrors.Exceeded(account.RetryAfter);
    }

    private static TotpFactorStatus ToStatus(
        Guid userId,
        StoredTotpFactor? factor)
        => factor?.State == TotpFactorState.Enabled
            ? new TotpFactorStatus(
                userId,
                IsEnabled: true,
                factor.RecoveryCodesRemaining,
                factor.EnabledAt)
            : new TotpFactorStatus(
                userId,
                IsEnabled: false,
                RecoveryCodesRemaining: 0,
                EnabledAt: null);

    private static Error? ValidateRequest(Guid userId, string? clientKey)
    {
        if (userId == Guid.Empty)
        {
            return Validation("userId", "UserId is required.");
        }

        return clientKey is { Length: > RateLimitLimits.MaximumClientKeyLength }
            ? Validation(
                "clientKey",
                "ClientKey exceeds the supported length.")
            : null;
    }

    private static Error? ValidateActiveUser(
        IdentityUser<TProfile>? user,
        DateTimeOffset now)
    {
        if (user is null)
        {
            return new Error(
                IdentityErrorCodes.UserNotFound,
                "User not found.",
                ErrorType.NotFound);
        }

        if (user.DeletedAt is not null)
        {
            return new Error(
                IdentityErrorCodes.UserDeleted,
                "User is deleted.",
                ErrorType.Conflict);
        }

        return user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now)
                ? new Error(
                    IdentityErrorCodes.AuthenticationBlocked,
                    "Authentication is blocked.",
                    ErrorType.Forbidden)
                : null;
    }

    private static string? NormalizeClientKey(string? clientKey)
        => string.IsNullOrWhiteSpace(clientKey)
            ? null
            : clientKey.Trim();

    private static Error Validation(string field, string message)
        => new(
            IdentityErrorCodes.Validation,
            "Validation failed.",
            ErrorType.Validation,
            new ValidationDetails(
                new Dictionary<string, string[]> { [field] = [message] }));

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult Fail(IIdentityOpScope op, Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail<T>(result.Errors);
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
