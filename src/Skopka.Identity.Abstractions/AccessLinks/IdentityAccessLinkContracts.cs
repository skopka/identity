using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.AccessLinks;

/// <summary>Independent lifetime for a trusted host-issued access link.</summary>
public sealed class IdentityAccessLinkOptions
{
    /// <summary>Lifetime of an issued access link, independently of password-reset tokens. Maximum 30 days.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(7);
}

/// <summary>A trusted host request. Scope is a server-selected site identifier, never an untrusted request value.</summary>
public sealed record IssueIdentityAccessLinkCommand(Guid UserId, long ExpectedVersion, string Scope, bool InvalidateExisting);
public sealed record IssuedIdentityAccessLink(string Token, DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"{nameof(IssuedIdentityAccessLink)} {{ Token = [redacted], ExpiresAt = {ExpiresAt} }}";
}
public sealed record IdentityAccessLinkInfo(DateTimeOffset ExpiresAt);
public sealed record BeginIdentityAccessLinkEnrollmentCommand(string Token, string Scope, string? ClientKey)
{
    public override string ToString() => $"{nameof(BeginIdentityAccessLinkEnrollmentCommand)} {{ Token = [redacted] }}";
}
public sealed record IdentityAccessLinkEnrollment(Guid EnrollmentId, string Secret, DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"{nameof(IdentityAccessLinkEnrollment)} {{ EnrollmentId = {EnrollmentId}, Secret = [redacted], ExpiresAt = {ExpiresAt} }}";
}
public sealed record CompleteIdentityAccessLinkCommand(string Token, string Scope, Guid EnrollmentId, string Code, string NewPassword, string? ClientKey)
{
    public override string ToString() => $"{nameof(CompleteIdentityAccessLinkCommand)} {{ [redacted] }}";
}
public sealed record CompletedIdentityAccessLink<TProfile>(IdentityUser<TProfile> User, IReadOnlyList<string> RecoveryCodes)
{
    public override string ToString() => $"{nameof(CompletedIdentityAccessLink<TProfile>)} {{ RecoveryCodes = [redacted] }}";
}

/// <summary>Trusted host issuance and one-use password and TOTP enrollment.</summary>
public interface IIdentityAccessLinkService<TProfile>
{
    /// <summary>Supersedes prior links and optionally invalidates existing password, authenticator and sessions atomically.</summary>
    Task<OperationResult<IssuedIdentityAccessLink>> IssueAsync(IssueIdentityAccessLinkCommand command, CancellationToken cancellationToken);
    /// <summary>Checks the link without changing its state.</summary>
    Task<OperationResult<IdentityAccessLinkInfo>> InspectAsync(string token, string scope, CancellationToken cancellationToken);
    /// <summary>Creates a pending authenticator secret without replacing existing credentials.</summary>
    Task<OperationResult<IdentityAccessLinkEnrollment>> BeginEnrollmentAsync(BeginIdentityAccessLinkEnrollmentCommand command, CancellationToken cancellationToken);
    /// <summary>Verifies the authenticator and atomically installs credentials while consuming the link.</summary>
    Task<OperationResult<CompletedIdentityAccessLink<TProfile>>> CompleteAsync(CompleteIdentityAccessLinkCommand command, CancellationToken cancellationToken);
    /// <summary>Removes a bounded batch of expired links.</summary>
    Task<int> PruneAsync(CancellationToken cancellationToken);
}
