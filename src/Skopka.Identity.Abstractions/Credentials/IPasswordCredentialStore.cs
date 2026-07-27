using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Credentials;

public interface IPasswordCredentialStore<TProfile>
{
    Task<string?> FindPasswordVerifierAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult> ReplacePasswordVerifierAsync(
        Guid userId,
        long expectedVersion,
        string? expectedPasswordVerifier,
        string? passwordVerifier,
        string? newSecurityStamp,
        DateTimeOffset now,
        CancellationToken ct);
}
