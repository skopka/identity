namespace Skopka.Identity.Verification;

public interface IVerificationMethodProvider
{
    string Method { get; }

    Task<IssuedVerificationMethodChallenge> IssueAsync(
        VerificationMethodContext context,
        CancellationToken ct);

    Task<bool> VerifyAsync(
        VerificationMethodContext context,
        string verifier,
        string response,
        CancellationToken ct);
}
