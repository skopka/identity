using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Users;

namespace Skopka.Identity.Verification;

public sealed class IdentityVerificationService<TProfile>
    : IIdentityVerificationService<TProfile>
{
    private readonly IVerificationChallengeStore<TProfile> challengeStore;
    private readonly IIdentityUserStore<TProfile> userStore;
    private readonly IReadOnlyDictionary<string, IVerificationMethodProvider> methods;
    private readonly VerificationOptions options;
    private readonly IIdentityMetrics metrics;
    private readonly IdentityRateLimitOptions rateLimitOptions;
    private readonly IIdentityRateLimiter<TProfile>? rateLimiter;

    public IdentityVerificationService(
        IVerificationChallengeStore<TProfile> challengeStore,
        IIdentityUserStore<TProfile> userStore,
        IEnumerable<IVerificationMethodProvider> methodProviders,
        VerificationOptions options,
        IIdentityMetrics metrics,
        IdentityRateLimitOptions rateLimitOptions,
        IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters)
    {
        this.challengeStore = challengeStore;
        this.userStore = userStore;
        this.options = options;
        this.metrics = metrics;
        this.rateLimitOptions = rateLimitOptions;
        rateLimiter = rateLimiters.FirstOrDefault();

        ValidateOptions(options);
        methods = methodProviders.ToDictionary(
            provider => provider.Method,
            StringComparer.Ordinal);
    }

    public async Task<OperationResult<IssuedVerificationChallenge>> BeginAsync(
        BeginVerificationCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("verification.begin");
        var validationError = ValidateBeginCommand(cmd);
        if (validationError is not null)
        {
            return Fail<IssuedVerificationChallenge>(op, validationError);
        }

        if (!methods.TryGetValue(cmd.Method, out var method))
        {
            return Fail<IssuedVerificationChallenge>(
                op,
                VerificationErrors.MethodUnavailable(cmd.Method));
        }

        var now = DateTimeOffset.UtcNow;
        if (rateLimiter is not null)
        {
            var clientKey = NormalizeClientKey(cmd.ClientKey);
            if (clientKey is not null)
            {
                var clientDecision = await rateLimiter.HitAsync(
                    new RateLimitRequest(
                        IdentityRateLimitScopes.VerificationClient,
                        clientKey,
                        rateLimitOptions.VerificationClientPermitLimit,
                        rateLimitOptions.VerificationClientWindow),
                    ct);
                if (!clientDecision.IsAllowed)
                {
                    return Fail<IssuedVerificationChallenge>(
                        op,
                        IdentityRateLimitErrors.Exceeded(
                            clientDecision.RetryAfter));
                }
            }
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<IssuedVerificationChallenge>(op, userError);
        }

        if (rateLimiter is not null)
        {
            var intentDecision = await rateLimiter.HitAsync(
                new RateLimitRequest(
                    IdentityRateLimitScopes.VerificationIntent,
                    BuildVerificationIntentKey(cmd),
                    rateLimitOptions.VerificationIntentPermitLimit,
                    rateLimitOptions.VerificationIntentWindow,
                    rateLimitOptions.VerificationResendCooldown),
                ct);
            if (!intentDecision.IsAllowed)
            {
                return Fail<IssuedVerificationChallenge>(
                    op,
                    IdentityRateLimitErrors.Exceeded(
                        intentDecision.RetryAfter));
            }

            var accountDecision = await rateLimiter.HitAsync(
                new RateLimitRequest(
                    IdentityRateLimitScopes.VerificationAccount,
                    user!.Id.ToString("N"),
                    rateLimitOptions.VerificationAccountPermitLimit,
                    rateLimitOptions.VerificationAccountWindow),
                ct);
            if (!accountDecision.IsAllowed)
            {
                return Fail<IssuedVerificationChallenge>(
                    op,
                    IdentityRateLimitErrors.Exceeded(
                        accountDecision.RetryAfter));
            }
        }

        var challengeId = Guid.NewGuid();
        var context = new VerificationMethodContext(
            challengeId,
            user!.Id,
            cmd.Purpose,
            cmd.Binding);
        var methodChallenge = await method.IssueAsync(context, ct);

        if (string.IsNullOrWhiteSpace(methodChallenge.Verifier)
            || methodChallenge.Verifier.Length
                > VerificationLimits.MaximumVerifierLength)
        {
            throw new InvalidOperationException(
                $"Verification method '{method.Method}' produced an invalid verifier.");
        }

        var expiresAt = now.Add(options.ChallengeLifetime);
        var challenge = new NewVerificationChallenge(
            challengeId,
            user.Id,
            cmd.Purpose,
            cmd.Binding,
            method.Method,
            methodChallenge.Verifier,
            user.SecurityStamp,
            options.MaxAttempts,
            expiresAt);
        var result = await challengeStore.CreateAsync(challenge, now, ct);
        if (!result.IsSuccess)
        {
            return Finish<IssuedVerificationChallenge>(op, result);
        }

        op.Success();
        return OperationResultFactory.Success(
            new IssuedVerificationChallenge(
                challengeId,
                method.Method,
                expiresAt,
                methodChallenge.DeliveryCode));
    }

    public async Task<OperationResult<VerificationProof>> VerifyAsync(
        VerifyVerificationChallengeCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("verification.verify");

        if (cmd.ChallengeId == Guid.Empty || cmd.UserId == Guid.Empty)
        {
            return Fail<VerificationProof>(
                op,
                VerificationErrors.ChallengeInvalid());
        }

        if (string.IsNullOrEmpty(cmd.Response)
            || cmd.Response.Length > options.MaximumResponseLength)
        {
            return Fail<VerificationProof>(
                op,
                VerificationErrors.ResponseInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var challenge = await challengeStore.FindByIdAsync(cmd.ChallengeId, ct);
        var challengeError = ValidatePendingChallenge(
            challenge,
            cmd.UserId,
            now);
        if (challengeError is not null)
        {
            return Fail<VerificationProof>(op, challengeError);
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<VerificationProof>(op, userError);
        }

        if (!string.Equals(
                user!.SecurityStamp,
                challenge!.SecurityStamp,
                StringComparison.Ordinal))
        {
            return Fail<VerificationProof>(
                op,
                VerificationErrors.ChallengeInvalid());
        }

        if (!methods.TryGetValue(challenge.Method, out var method))
        {
            return Fail<VerificationProof>(
                op,
                VerificationErrors.MethodUnavailable(challenge.Method));
        }

        var context = new VerificationMethodContext(
            challenge.Id,
            challenge.UserId,
            challenge.Purpose,
            challenge.Binding);
        var succeeded = await method.VerifyAsync(
            context,
            challenge.Verifier,
            cmd.Response,
            ct);

        string? proof = null;
        string? proofHash = null;
        DateTimeOffset? proofExpiresAt = null;
        if (succeeded)
        {
            proof = VerificationProofCodec.Generate();
            proofHash = VerificationProofCodec.Hash(proof);
            proofExpiresAt = Min(
                now.Add(options.ProofLifetime),
                challenge.ExpiresAt);
        }

        var result = await challengeStore.RecordAttemptAsync(
            challenge.Id,
            challenge.Version,
            succeeded,
            proofHash,
            proofExpiresAt,
            now,
            ct);
        if (!result.IsSuccess)
        {
            return Finish<VerificationProof>(op, result);
        }

        if (!succeeded)
        {
            var error = result.Value.State == VerificationChallengeState.Locked
                ? VerificationErrors.AttemptsExceeded()
                : VerificationErrors.ResponseInvalid();
            return Fail<VerificationProof>(op, error);
        }

        op.Success();
        return OperationResultFactory.Success(
            new VerificationProof(
                challenge.Id,
                proof!,
                proofExpiresAt!.Value));
    }

    public async Task<OperationResult> ConsumeAsync(
        ConsumeVerificationProofCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("verification.consume");

        if (cmd.ChallengeId == Guid.Empty
            || cmd.UserId == Guid.Empty
            || !IsValidRequiredValue(
                cmd.Purpose,
                VerificationLimits.MaximumPurposeLength)
            || !IsValidRequiredValue(
                cmd.Binding,
                VerificationLimits.MaximumBindingLength)
            || string.IsNullOrWhiteSpace(cmd.Proof)
            || cmd.Proof.Length > VerificationLimits.MaximumProofLength)
        {
            return Fail(op, VerificationErrors.ProofInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var challenge = await challengeStore.FindByIdAsync(
            cmd.ChallengeId,
            ct);
        if (challenge is null
            || challenge.State != VerificationChallengeState.Verified
            || challenge.ProofHash is null
            || challenge.ProofExpiresAt is null
            || challenge.ProofExpiresAt <= now
            || challenge.UserId != cmd.UserId
            || !string.Equals(
                challenge.Purpose,
                cmd.Purpose,
                StringComparison.Ordinal)
            || !string.Equals(
                challenge.Binding,
                cmd.Binding,
                StringComparison.Ordinal)
            || !VerificationProofCodec.Matches(
                challenge.ProofHash,
                cmd.Proof))
        {
            return Fail(op, VerificationErrors.ProofInvalid());
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        if (!string.Equals(
                user!.SecurityStamp,
                challenge.SecurityStamp,
                StringComparison.Ordinal))
        {
            return Fail(op, VerificationErrors.ProofInvalid());
        }

        var result = await challengeStore.ConsumeProofAsync(
            challenge.Id,
            challenge.Version,
            challenge.UserId,
            challenge.Purpose,
            challenge.Binding,
            challenge.ProofHash,
            challenge.SecurityStamp,
            now,
            ct);
        return Finish(op, result);
    }

    private static Error? ValidateBeginCommand(BeginVerificationCommand cmd)
    {
        if (cmd.UserId == Guid.Empty)
        {
            return IdentityErrors.Validation("userId", "UserId is required.");
        }

        if (!IsValidRequiredValue(
                cmd.Purpose,
                VerificationLimits.MaximumPurposeLength))
        {
            return IdentityErrors.Validation(
                "purpose",
                "Purpose is required and exceeds the supported length.");
        }

        if (!IsValidRequiredValue(
                cmd.Binding,
                VerificationLimits.MaximumBindingLength))
        {
            return IdentityErrors.Validation(
                "binding",
                "Binding is required and exceeds the supported length.");
        }

        if (!IsValidRequiredValue(
                cmd.Method,
                VerificationLimits.MaximumMethodLength))
        {
            return IdentityErrors.Validation(
                "method",
                "Method is required and exceeds the supported length.");
        }

        if (cmd.ClientKey is { Length: > RateLimitLimits.MaximumClientKeyLength })
        {
            return IdentityErrors.Validation(
                "clientKey",
                "ClientKey exceeds the supported length.");
        }

        return null;
    }

    private static Error? ValidatePendingChallenge(
        StoredVerificationChallenge? challenge,
        Guid userId,
        DateTimeOffset now)
    {
        if (challenge is null
            || challenge.UserId != userId
            || challenge.ExpiresAt <= now)
        {
            return VerificationErrors.ChallengeInvalid();
        }

        if (challenge.State == VerificationChallengeState.Locked
            || challenge.FailedAttemptCount >= challenge.MaxAttempts)
        {
            return VerificationErrors.AttemptsExceeded();
        }

        return challenge.State == VerificationChallengeState.Pending
            ? null
            : VerificationErrors.ChallengeInvalid();
    }

    private static Error? ValidateActiveUser(
        IdentityUser<TProfile>? user,
        DateTimeOffset now)
    {
        if (user is null)
        {
            return IdentityErrors.NotFound();
        }

        if (user.DeletedAt is not null)
        {
            return IdentityErrors.Deleted();
        }

        return IsBlocked(user, now)
            ? VerificationErrors.Blocked()
            : null;
    }

    private static bool IsBlocked(
        IdentityUser<TProfile> user,
        DateTimeOffset now)
        => user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now);

    private static bool IsValidRequiredValue(string? value, int maximumLength)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length <= maximumLength;

    private static string BuildVerificationIntentKey(
        BeginVerificationCommand cmd)
        => $"{cmd.UserId:N}|{cmd.Purpose.Length}:{cmd.Purpose}"
            + $"|{cmd.Binding.Length}:{cmd.Binding}|{cmd.Method}";

    private static string? NormalizeClientKey(string? clientKey)
        => string.IsNullOrWhiteSpace(clientKey)
            ? null
            : clientKey.Trim();

    private static DateTimeOffset Min(
        DateTimeOffset first,
        DateTimeOffset second)
        => first <= second ? first : second;

    private static void ValidateOptions(VerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.ChallengeLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.ChallengeLifetime));
        }

        if (options.ProofLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.ProofLifetime));
        }

        if (options.MaxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaxAttempts));
        }

        if (options.MaximumResponseLength <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.MaximumResponseLength));
        }
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult Fail(
        IIdentityOpScope op,
        Error error)
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
