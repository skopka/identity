using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Verification;

public interface IIdentityVerificationService<TProfile>
{
    Task<OperationResult<IssuedVerificationChallenge>> BeginAsync(
        BeginVerificationCommand cmd,
        CancellationToken ct);

    Task<OperationResult<VerificationProof>> VerifyAsync(
        VerifyVerificationChallengeCommand cmd,
        CancellationToken ct);

    Task<OperationResult> ConsumeAsync(
        ConsumeVerificationProofCommand cmd,
        CancellationToken ct);
}
