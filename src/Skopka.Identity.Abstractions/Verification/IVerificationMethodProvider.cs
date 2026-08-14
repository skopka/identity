using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Verification;

public interface IVerificationMethodProvider
{
    string Method { get; }

    Task<OperationResult> CheckAvailabilityAsync(
        VerificationMethodContext context,
        CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Success());

    Task<IssuedVerificationMethodChallenge> IssueAsync(
        VerificationMethodContext context,
        CancellationToken ct);

    Task<bool> VerifyAsync(
        VerificationMethodContext context,
        string verifier,
        string response,
        CancellationToken ct);
}
