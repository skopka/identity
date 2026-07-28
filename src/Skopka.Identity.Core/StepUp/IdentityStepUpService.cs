using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.StepUp.Commands;
using Skopka.Identity.Verification;

namespace Skopka.Identity.StepUp;

public sealed class IdentityStepUpService<TProfile>(
    IIdentityVerificationService<TProfile> verificationService,
    IVerificationChallengeStore<TProfile> challengeStore,
    IStepUpPolicyProvider<TProfile> policyProvider,
    IIdentityMetrics metrics)
    : IIdentityStepUpService<TProfile>
{
    private const string IntentBindingVersion = "step-up:v1";

    public async Task<OperationResult<IssuedVerificationChallenge>> BeginAsync(
        BeginStepUpCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("step_up.begin");

        var validationError = ValidateContext(
            cmd.UserId,
            cmd.Action,
            cmd.Binding);
        validationError ??= ValidateMethod(cmd.Method);
        validationError ??= ValidateClientKey(cmd.ClientKey);
        if (validationError is not null)
        {
            return Fail<IssuedVerificationChallenge>(op, validationError);
        }

        var context = new StepUpAuthorizationContext(
            cmd.UserId,
            cmd.Action,
            cmd.Binding);
        var requirement = await policyProvider.GetRequirementAsync(context, ct);
        if (requirement is null)
        {
            return Fail<IssuedVerificationChallenge>(
                op,
                StepUpErrors.PolicyUnavailable(cmd.Action));
        }

        ValidateRequirement(requirement);
        if (!IsMethodAllowed(requirement, cmd.Method))
        {
            return Fail<IssuedVerificationChallenge>(
                op,
                StepUpErrors.MethodNotAllowed(cmd.Method));
        }

        var intentBinding = BuildIntentBinding(cmd.Action, cmd.Binding);
        var result = await verificationService.BeginAsync(
            new BeginVerificationCommand(
                cmd.UserId,
                requirement.Purpose,
                intentBinding,
                cmd.Method,
                cmd.ClientKey),
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult<StepUpDecision>>
        AuthorizeAsync(
            AuthorizeStepUpCommand cmd,
            CancellationToken ct)
    {
        using var op = metrics.Begin("step_up.authorize");

        var validationError = ValidateContext(
            cmd.UserId,
            cmd.Action,
            cmd.Binding);
        validationError ??= ValidateProof(cmd.ChallengeId, cmd.Proof);
        if (validationError is not null)
        {
            return Fail<StepUpDecision>(op, validationError);
        }

        var context = new StepUpAuthorizationContext(
            cmd.UserId,
            cmd.Action,
            cmd.Binding);
        var requirement = await policyProvider.GetRequirementAsync(context, ct);
        if (requirement is null)
        {
            return Fail<StepUpDecision>(
                op,
                StepUpErrors.PolicyUnavailable(cmd.Action));
        }

        ValidateRequirement(requirement);

        var now = DateTimeOffset.UtcNow;
        var intentBinding = BuildIntentBinding(cmd.Action, cmd.Binding);
        var challenge = await challengeStore.FindByIdAsync(
            cmd.ChallengeId,
            ct);
        if (!MatchesProofIntent(
                challenge,
                cmd,
                requirement,
                intentBinding,
                now))
        {
            return Fail<StepUpDecision>(
                op,
                StepUpErrors.ProofInvalid());
        }

        if (!IsMethodAllowed(requirement, challenge!.Method))
        {
            return Fail<StepUpDecision>(
                op,
                StepUpErrors.MethodNotAllowed(challenge.Method));
        }

        var consumeResult = await verificationService.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.Id,
                cmd.UserId,
                requirement.Purpose,
                intentBinding,
                cmd.Proof),
            ct);
        if (!consumeResult.IsSuccess)
        {
            return Finish<StepUpDecision>(op, consumeResult);
        }

        op.Success();
        return OperationResultFactory.Success(
            new StepUpDecision(
                cmd.UserId,
                cmd.Action,
                cmd.Binding,
                requirement.Purpose,
                challenge.Id,
                challenge.Method,
                requirement.AssuranceLevel,
                challenge.VerifiedAt!.Value,
                now));
    }

    private static bool MatchesProofIntent(
        StoredVerificationChallenge? challenge,
        AuthorizeStepUpCommand cmd,
        StepUpRequirement requirement,
        string intentBinding,
        DateTimeOffset now)
    {
        if (challenge is null
            || challenge.State != VerificationChallengeState.Verified
            || challenge.UserId != cmd.UserId
            || challenge.VerifiedAt is null
            || challenge.VerifiedAt > now
            || challenge.ProofExpiresAt is null
            || challenge.ProofExpiresAt <= now
            || !string.Equals(
                challenge.Purpose,
                requirement.Purpose,
                StringComparison.Ordinal)
            || !string.Equals(
                challenge.Binding,
                intentBinding,
                StringComparison.Ordinal))
        {
            return false;
        }

        return requirement.MaximumAge is null
            || now - challenge.VerifiedAt.Value <= requirement.MaximumAge.Value;
    }

    private static string BuildIntentBinding(
        string action,
        string resourceBinding)
    {
        // Keep the Verification binding bounded while preserving both intent dimensions.
        var value = $"{IntentBindingVersion}|{action.Length}:{action}|"
            + $"{resourceBinding.Length}:{resourceBinding}";
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private static bool IsMethodAllowed(
        StepUpRequirement requirement,
        string method)
        => requirement.AllowedMethods.Contains(
            method,
            StringComparer.Ordinal);

    private static Error? ValidateContext(
        Guid userId,
        string action,
        string binding)
    {
        if (userId == Guid.Empty)
        {
            return StepUpErrors.Validation(
                "userId",
                "UserId is required.");
        }

        if (!IsValidRequiredValue(
                action,
                StepUpLimits.MaximumActionLength))
        {
            return StepUpErrors.Validation(
                "action",
                "Action is required and exceeds the supported length.");
        }

        if (!IsValidRequiredValue(
                binding,
                VerificationLimits.MaximumBindingLength))
        {
            return StepUpErrors.Validation(
                "binding",
                "Binding is required and exceeds the supported length.");
        }

        return null;
    }

    private static Error? ValidateMethod(string method)
        => IsValidRequiredValue(
            method,
            VerificationLimits.MaximumMethodLength)
            ? null
            : StepUpErrors.Validation(
                "method",
                "Method is required and exceeds the supported length.");

    private static Error? ValidateClientKey(string? clientKey)
        => clientKey is not
            {
                Length: > RateLimitLimits.MaximumClientKeyLength
            }
            ? null
            : StepUpErrors.Validation(
                "clientKey",
                "ClientKey exceeds the supported length.");

    private static Error? ValidateProof(
        Guid challengeId,
        string proof)
    {
        if (challengeId == Guid.Empty
            || string.IsNullOrWhiteSpace(proof)
            || proof.Length > VerificationLimits.MaximumProofLength)
        {
            return StepUpErrors.ProofInvalid();
        }

        return null;
    }

    private static bool IsValidRequiredValue(
        string? value,
        int maximumLength)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length <= maximumLength;

    private static void ValidateRequirement(StepUpRequirement requirement)
    {
        if (!IsValidRequiredValue(
                requirement.Purpose,
                VerificationLimits.MaximumPurposeLength))
        {
            throw new InvalidOperationException(
                "Step-up policy produced an invalid verification purpose.");
        }

        if (requirement.AllowedMethods is null
            || requirement.AllowedMethods.Count == 0
            || requirement.AllowedMethods.Any(
                method => !IsValidRequiredValue(
                    method,
                    VerificationLimits.MaximumMethodLength)))
        {
            throw new InvalidOperationException(
                "Step-up policy must contain valid allowed verification methods.");
        }

        if (requirement.AssuranceLevel < 1)
        {
            throw new InvalidOperationException(
                "Step-up policy produced an invalid assurance level.");
        }

        if (requirement.MaximumAge is { } maximumAge
            && maximumAge <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Step-up policy maximum age must be positive.");
        }
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult<T> result)
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

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail<T>(result.Errors);
    }
}
