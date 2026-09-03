using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.WebAuthn;

public sealed record NewWebAuthnCredential(
    Guid Id,
    Guid UserId,
    byte[] CredentialId,
    byte[] PublicKey,
    WebAuthnAlgorithm Algorithm,
    long SignatureCounter,
    Guid AuthenticatorId,
    bool BackedUp,
    string? Label);

public sealed record StoredWebAuthnCredential(
    Guid Id,
    Guid UserId,
    byte[] CredentialId,
    byte[] PublicKey,
    WebAuthnAlgorithm Algorithm,
    long SignatureCounter,
    Guid AuthenticatorId,
    bool BackedUp,
    string? Label,
    long Version,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

public interface IWebAuthnCredentialStore<TProfile>
{
    /// <summary>
    /// Looked up by the authenticator's own identifier, which is what an
    /// assertion arrives carrying. Credential ids are unique across users, so
    /// this answers before a user is known — which is how a passkey signs in
    /// someone who typed nothing.
    /// </summary>
    Task<StoredWebAuthnCredential?> FindByCredentialIdAsync(
        byte[] credentialId,
        CancellationToken ct);

    Task<IReadOnlyList<StoredWebAuthnCredential>> ListByUserIdAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult> CreateAsync(
        NewWebAuthnCredential credential,
        DateTimeOffset now,
        CancellationToken ct);

    /// <summary>
    /// Writes the counter an accepted assertion reported, along with the moment
    /// it was accepted. False when the row moved on since it was read, which is
    /// the same assertion arriving twice at once. Whether the counter may move
    /// to that value at all is decided before this is called: a store keeps
    /// what it is told, it does not judge it.
    /// </summary>
    Task<OperationResult<bool>> TryAdvanceCounterAsync(
        Guid id,
        long expectedVersion,
        long counter,
        DateTimeOffset usedAt,
        CancellationToken ct);

    Task<OperationResult> RemoveAsync(
        Guid userId,
        Guid id,
        CancellationToken ct);
}
