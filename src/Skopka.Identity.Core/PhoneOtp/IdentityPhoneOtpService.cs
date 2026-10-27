using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;
using Skopka.Identity.Verification;

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
    IIdentityPhoneNumberPolicy phonePolicy)
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

    public async Task<OperationResult<VerifiedPhoneOtp<TProfile>>> VerifyAsync(
        VerifyPhoneOtpCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("phone_otp.verify");
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
            challenge.Binding, ct);
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
