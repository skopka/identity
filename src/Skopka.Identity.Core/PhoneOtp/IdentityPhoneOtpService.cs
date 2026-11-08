using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;
using Skopka.Identity.Registration;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.PhoneOtp;

public sealed class IdentityPhoneOtpService<TProfile>(
    IIdentityNormalizer normalizer,
    IIdentityVerificationService<TProfile> verification,
    IVerificationChallengeStore<TProfile> challengeStore,
    IIdentityUserLookupService<TProfile> lookup,
    IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters,
    IdentityRateLimitOptions rateLimitOptions,
    PhoneOtpOptions options,
    IIdentityMetrics metrics,
    IIdentitySecurityEventObserver securityEvents,
    IIdentityPhoneNumberPolicy phonePolicy,
    IIdentityRegistrationStore<TProfile>? registrationStore = null,
    IIdentityUserStore<TProfile>? userStore = null,
    IUserOperationPolicy? userPolicy = null)
    : IIdentityPhoneOtpService<TProfile>
{
    public IdentityPhoneOtpService(
        IIdentityNormalizer normalizer,
        IIdentityVerificationService<TProfile> verification,
        IVerificationChallengeStore<TProfile> challengeStore,
        IIdentityUserLookupService<TProfile> lookup,
        IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters,
        IdentityRateLimitOptions rateLimitOptions,
        PhoneOtpOptions options,
        IIdentityMetrics metrics,
        IIdentitySecurityEventObserver securityEvents)
        : this(normalizer, verification, challengeStore, lookup, rateLimiters,
            rateLimitOptions, options, metrics, securityEvents,
            new IdentityPhoneNumberPolicy(normalizer, options))
    {
    }

    private readonly IIdentityRateLimiter<TProfile>? rateLimiter =
        rateLimiters.FirstOrDefault();

    public async Task<OperationResult<IssuedPhoneOtpChallenge>> BeginAsync(
        BeginPhoneOtpCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("phone_otp.begin");
        ArgumentNullException.ThrowIfNull(normalizer);
        var normalized = phonePolicy.Normalize(command.Phone);
        if (!normalized.IsSuccess)
        {
            op.Failure(normalized.Errors.First().Code);
            return OperationResultFactory.Fail<IssuedPhoneOtpChallenge>(normalized.Errors);
        }
        var phone = normalized.Value;

        if (rateLimiter is null)
        {
            throw new InvalidOperationException(
                "Phone OTP requires a persistent Identity rate limiter.");
        }

        var phoneBudget = await rateLimiter.HitAsync(
            new RateLimitRequest(
                "phone_otp.daily_phone",
                phone,
                options.DailyPhonePermitLimit,
                options.DailyWindow),
            ct);
        if (!phoneBudget.IsAllowed)
        {
            return Fail<IssuedPhoneOtpChallenge>(op,
                IdentityRateLimitErrors.Exceeded(phoneBudget.RetryAfter));
        }

        if (!string.IsNullOrWhiteSpace(command.ClientKey))
        {
            var clientBudget = await rateLimiter.HitAsync(
                new RateLimitRequest(
                    "phone_otp.daily_client",
                    command.ClientKey.Trim(),
                    options.DailyClientPermitLimit,
                    options.DailyWindow),
                ct);
            if (!clientBudget.IsAllowed)
            {
                return Fail<IssuedPhoneOtpChallenge>(op,
                    IdentityRateLimitErrors.Exceeded(clientBudget.RetryAfter));
            }
        }

        var issued = await verification.BeginAsync(
            new BeginVerificationCommand(
                Guid.Empty,
                VerificationPurposes.PhoneSignIn,
                phone,
                VerificationMethods.OneTimeCode,
                command.ClientKey),
            ct);
        if (!issued.IsSuccess)
        {
            return Finish<IssuedPhoneOtpChallenge>(op, issued);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.PhoneCodeRequested,
            DateTimeOffset.UtcNow,
            null);
        op.Success();
        return OperationResultFactory.Success(new IssuedPhoneOtpChallenge(
            issued.Value.ChallengeId,
            phone,
            issued.Value.ExpiresAt,
            rateLimitOptions.VerificationResendCooldown,
            issued.Value.DeliveryCode!));
    }

    public async Task<OperationResult<VerificationProof>> VerifyForBindingAsync(
        VerifyPhoneOtpCommand command, CancellationToken ct)
    {
        using var op = metrics.Begin("phone_otp.verify_binding");
        var result = await VerifyForBindingCoreAsync(command, ct);
        if (result.IsSuccess) op.Success();
        else
        {
            op.Failure(result.Errors.First().Code);
            securityEvents.Observe(IdentitySecurityEventTypes.PhoneCodeInvalid, DateTimeOffset.UtcNow, null);
        }
        return result;
    }

    private async Task<OperationResult<VerificationProof>> VerifyForBindingCoreAsync(
        VerifyPhoneOtpCommand command, CancellationToken ct)
    {
        if (command is null) return OperationResultFactory.Fail<VerificationProof>(new Error(
            IdentityErrorCodes.VerificationChallengeInvalid, "Verification challenge is invalid or expired.", ErrorType.Validation));
        var challenge = await challengeStore.FindByIdAsync(command.ChallengeId, ct);
        if (challenge is null || challenge.UserId != Guid.Empty
            || challenge.Purpose != VerificationPurposes.PhoneSignIn)
            return OperationResultFactory.Fail<VerificationProof>(new Error(
                IdentityErrorCodes.VerificationChallengeInvalid,
                "Verification challenge is invalid or expired.", ErrorType.Validation));

        return await verification.VerifyAsync(new VerifyVerificationChallengeCommand(
            command.ChallengeId, Guid.Empty, command.Code, command.ClientKey), ct);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> BindVerifiedPhoneAsync(
        BindVerifiedPhoneCommand command, CancellationToken ct)
    {
        using var op = metrics.Begin("phone_otp.bind");
        var result = await BindVerifiedPhoneCoreAsync(command, ct);
        if (result.IsSuccess)
        {
            op.Success();
            securityEvents.Observe(IdentitySecurityEventTypes.PhoneConfirmed, DateTimeOffset.UtcNow, result.Value.Id);
        }
        else op.Failure(result.Errors.First().Code);
        return result;
    }

    private async Task<OperationResult<IdentityUser<TProfile>>> BindVerifiedPhoneCoreAsync(
        BindVerifiedPhoneCommand command, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (command is null || command.Proof is null || string.IsNullOrEmpty(command.Proof.Token) || command.Phone is null)
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(new Error(
                IdentityErrorCodes.VerificationProofInvalid, "Verification proof is invalid or expired.", ErrorType.Unauthorized));
        var scopeError = PhoneScopeValidator.Validate(command.PhoneScope);
        if (scopeError is not null)
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(scopeError);
        var normalized = phonePolicy.Normalize(command.Phone);
        if (!normalized.IsSuccess)
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(normalized.Errors);
        var challenge = await challengeStore.FindByIdAsync(command.Proof.ChallengeId, ct);
        if (challenge is null || challenge.UserId != Guid.Empty
            || challenge.Purpose != VerificationPurposes.PhoneSignIn
            || challenge.Binding != normalized.Value
            || challenge.State != VerificationChallengeState.Verified
            || challenge.ProofExpiresAt is null || challenge.ProofExpiresAt <= now || challenge.ProofHash is null
            || !VerificationProofCodec.Matches(challenge.ProofHash, command.Proof.Token))
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(new Error(
                IdentityErrorCodes.VerificationProofInvalid,
                "Verification proof is invalid or expired.", ErrorType.Unauthorized));
        if (registrationStore is null || userStore is null || userPolicy is null)
            return OperationResultFactory.Fail<IdentityUser<TProfile>>(new Error(
                IdentityErrorCodes.PhoneBindingUnavailable, "Phone binding is unavailable.", ErrorType.Forbidden));
        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (user is null) return OperationResultFactory.Fail<IdentityUser<TProfile>>(IdentityErrors.NotFound());
        if (!userPolicy.CanMutate(user.Flags)) return OperationResultFactory.Fail<IdentityUser<TProfile>>(IdentityErrors.Forbidden(user.Flags));
        if (user.DeletedAt is not null) return OperationResultFactory.Fail<IdentityUser<TProfile>>(IdentityErrors.Deleted());
        if (user.Version != command.ExpectedVersion) return OperationResultFactory.Fail<IdentityUser<TProfile>>(IdentityErrors.Concurrency());
        var name = normalizer.NormalizeUserName(user.UserName);
        var email = normalizer.NormalizeEmail(user.Email);
        var phone = normalizer.NormalizePhoneLoginIdentifier(normalized.Value);
        var keys = LoginIdentifierKeyBuilder.Create(normalizer, user.UserName, user.Email,
            normalized.Value, name, email, phone, out var error);
        if (error is not null) return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
        return await registrationStore.BindVerifiedPhoneAsync(user.Id, user.Version,
            new UpdatedHandles(user.UserName, name, user.Email, email, user.EmailConfirmed,
                normalized.Value, phone, true, keys)
            {
                PhoneScope = command.PhoneScope ?? user.PhoneScope,
            }, challenge.Id, challenge.Version,
            challenge.ProofHash, now, ct);
    }

    public async Task<OperationResult<VerifiedPhoneOtp<TProfile>>> VerifyAsync(
        VerifyPhoneOtpCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("phone_otp.verify");
        var scopeError = PhoneScopeValidator.Validate(command.PhoneScope);
        if (scopeError is not null)
        {
            return Fail<VerifiedPhoneOtp<TProfile>>(op, scopeError);
        }

        var challenge = await challengeStore.FindByIdAsync(
            command.ChallengeId, ct);
        if (challenge is null
            || challenge.UserId != Guid.Empty
            || challenge.Purpose != VerificationPurposes.PhoneSignIn)
        {
            return Fail<VerifiedPhoneOtp<TProfile>>(op, new Error(
                IdentityErrorCodes.VerificationChallengeInvalid,
                "Verification challenge is invalid or expired.",
                ErrorType.Validation));
        }

        var verified = await verification.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                command.ChallengeId,
                Guid.Empty,
                command.Code,
                command.ClientKey),
            ct);
        if (!verified.IsSuccess)
        {
            var code = verified.Errors.First().Code;
            securityEvents.Observe(
                code == IdentityErrorCodes.VerificationAttemptsExceeded
                    ? IdentitySecurityEventTypes.PhoneCodeAttemptsExceeded
                    : IdentitySecurityEventTypes.PhoneCodeInvalid,
                DateTimeOffset.UtcNow,
                null);
            return Finish<VerifiedPhoneOtp<TProfile>>(op, verified);
        }

        var found = await lookup.FindActiveByPhoneAsync(
            challenge.Binding, command.PhoneScope, ct);
        if (!found.IsSuccess)
        {
            if (found.Errors.Any(error => error.Code != IdentityErrorCodes.UserNotFound))
            {
                return Finish<VerifiedPhoneOtp<TProfile>>(op, found);
            }

            op.Success();
            return OperationResultFactory.Success(
                new VerifiedPhoneOtp<TProfile>(
                    challenge.Binding,
                    null,
                    verified.Value));
        }

        var user = found.Value;
        if (!user.PhoneConfirmed)
        {
            op.Success();
            return OperationResultFactory.Success(
                new VerifiedPhoneOtp<TProfile>(
                    challenge.Binding,
                    null,
                    verified.Value));
        }

        var now = DateTimeOffset.UtcNow;
        if (user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now))
        {
            return Fail<VerifiedPhoneOtp<TProfile>>(op, new Error(
                IdentityErrorCodes.AuthenticationBlocked,
                "Authentication is blocked.",
                ErrorType.Forbidden));
        }

        var consumed = await verification.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                verified.Value.ChallengeId,
                Guid.Empty,
                VerificationPurposes.PhoneSignIn,
                challenge.Binding,
                verified.Value.Token),
            ct);
        if (!consumed.IsSuccess)
        {
            return Finish<VerifiedPhoneOtp<TProfile>>(op, consumed);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.PhoneSignIn,
            now,
            user.Id);
        op.Success();
        return OperationResultFactory.Success(
            new VerifiedPhoneOtp<TProfile>(challenge.Binding, user, null));
    }

    private static OperationResult<T> Fail<T>(IIdentityOpScope op, Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail<T>(result.Errors);
    }
}
