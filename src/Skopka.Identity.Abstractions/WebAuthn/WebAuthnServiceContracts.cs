using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.WebAuthn;

public sealed class WebAuthnOptions
{
    /// <summary>
    /// The domain a credential is bound to. An authenticator will not answer
    /// for any other, which is what makes a credential un-phishable — so this
    /// is configuration rather than a request field.
    /// </summary>
    public string RelyingPartyId { get; set; } = string.Empty;

    /// <summary>
    /// The addresses the server's own pages are served from. Compared exactly.
    /// </summary>
    public IList<string> Origins { get; } = [];

    /// <summary>
    /// Whether the authenticator must verify the person and not merely notice
    /// one. On by default: a passkey that stands in for a password should be
    /// worth as much as one.
    /// </summary>
    public bool UserVerificationRequired { get; set; } = true;

    public int MaximumCredentialsPerUser { get; set; } = 10;
}

public sealed record WebAuthnCredentialDescriptor(
    Guid Id,
    Guid UserId,
    string? Label,
    bool BackedUp,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt);

public sealed record RegisterWebAuthnCredentialCommand(
    Guid UserId,
    byte[] ClientDataJson,
    byte[] AttestationObject,
    byte[] Challenge,
    string? Label = null,
    string? ClientKey = null);

public sealed record AuthenticateWebAuthnCommand(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AuthenticatorData,
    byte[] Signature,
    byte[] Challenge,
    string? ClientKey = null);

public sealed record RemoveWebAuthnCredentialCommand(
    Guid UserId,
    Guid CredentialId,
    long ExpectedVersion);

/// <summary>
/// The lifecycle of a public-key credential.
///
/// The ceremonies are verified here and not by the caller: a host that had to
/// remember to verify before persisting is a host that can forget. What the
/// host owns is the challenge — issuing it, spending it once — and what a
/// verified assertion is then allowed to do.
/// </summary>
public interface IIdentityWebAuthnService<TProfile>
{
    Task<OperationResult<IReadOnlyList<WebAuthnCredentialDescriptor>>> ListAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<WebAuthnCredentialDescriptor>> RegisterAsync(
        RegisterWebAuthnCredentialCommand command,
        CancellationToken ct);

    /// <summary>
    /// The user an accepted assertion belongs to. No handle is asked for: the
    /// credential names its owner, which is what lets someone sign in having
    /// typed nothing.
    /// </summary>
    Task<OperationResult<IdentityUser<TProfile>>> AuthenticateAsync(
        AuthenticateWebAuthnCommand command,
        CancellationToken ct);

    Task<OperationResult> RemoveAsync(
        RemoveWebAuthnCredentialCommand command,
        CancellationToken ct);
}
