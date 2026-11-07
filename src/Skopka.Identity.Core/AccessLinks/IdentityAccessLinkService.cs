using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Security;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;
using Skopka.Identity.Users;

namespace Skopka.Identity.AccessLinks;

public sealed class IdentityAccessLinkService<TProfile>(
    IIdentityAccessLinkStore<TProfile> links, IIdentityUserStore<TProfile> users,
    IUserOperationPolicy userPolicy, IPasswordHasher passwordHasher, PasswordPolicyOptions passwordOptions,
    IEnumerable<IPasswordValidator<TProfile>> passwordValidators, ITotpCodeProvider totp,
    ITotpSecretProtector protector, TotpOptions totpOptions, ISecurityStampGenerator stamps,
    IdentityAccessLinkOptions options, IIdentitySecurityEventObserver? securityEvents = null,
    IEnumerable<IIdentityRateLimiter<TProfile>>? rateLimiters = null, IdentityRateLimitOptions? rateLimitOptions = null)
    : IIdentityAccessLinkService<TProfile>
{
    private static Error Invalid() => new("identity.access_link.invalid", "The access link is invalid or expired.", ErrorType.Validation);
    private static OperationResult<T> Fail<T>() => OperationResultFactory.Fail<T>(Invalid());
    private static bool ValidScope(string? scope) => !string.IsNullOrWhiteSpace(scope)
        && scope.Length <= IdentitySessionContext.MaximumValueLength && !scope.Any(char.IsControl);
    public Task<int> PruneAsync(CancellationToken cancellationToken)
        => links.PruneAsync(DateTimeOffset.UtcNow, 500, cancellationToken);
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool TryId(string? token, out Guid id)
    {
        id = default;
        return token is { Length: 76 } && token[32] == '.' && Guid.TryParseExact(token[..32], "N", out id)
            && token[33..].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    }
    private static bool EqualHash(string expected, string token)
    {
        var actual = Hash(token);
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
    }
    private bool Mutable(IdentityUser<TProfile>? user, DateTimeOffset now) => user is not null
        && userPolicy.CanMutate(user.Flags) && user.DeletedAt is null
        && (user.BlockedAt is null || user.BlockedUntil is not null && user.BlockedUntil <= now);

    private async Task<(StoredIdentityAccessLink? Link, IdentityUser<TProfile>? User)> Read(string token, string scope, CancellationToken ct)
    {
        if (!ValidScope(scope) || !TryId(token, out var id)) return (null, null);
        var link = await links.FindAsync(id, ct);
        var now = DateTimeOffset.UtcNow;
        if (link is null || link.Consumed || link.ExpiresAt <= now || link.FailedAttempts >= 5
            || !string.Equals(link.Scope, scope, StringComparison.Ordinal) || !EqualHash(link.TokenHash, token)) return (null, null);
        var user = await users.FindByIdAsync(link.UserId, ct);
        return Mutable(user, now) && user!.Version == link.UserVersion ? (link, user) : (null, null);
    }

    public async Task<OperationResult<IssuedIdentityAccessLink>> IssueAsync(IssueIdentityAccessLinkCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = DateTimeOffset.UtcNow;
        if (!ValidScope(command.Scope) || options.Lifetime <= TimeSpan.Zero || options.Lifetime > TimeSpan.FromDays(30)) return Fail<IssuedIdentityAccessLink>();
        var user = await users.FindByIdAsync(command.UserId, cancellationToken);
        if (!Mutable(user, now) || user!.Version != command.ExpectedVersion) return Fail<IssuedIdentityAccessLink>();
        var id = Guid.NewGuid();
        var token = id.ToString("N") + "." + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var link = new StoredIdentityAccessLink(id, user.Id, user.Version + 1, command.Scope, Hash(token), now.Add(options.Lifetime), 1, null, null, null, 0, false);
        var issued = await links.IssueAsync(link, user.Version, command.InvalidateExisting, stamps.Generate(), now, cancellationToken);
        return issued.IsSuccess ? OperationResultFactory.Success(new IssuedIdentityAccessLink(token, link.ExpiresAt))
            : OperationResultFactory.Fail<IssuedIdentityAccessLink>(issued.Errors);
    }

    public async Task<OperationResult<IdentityAccessLinkInfo>> InspectAsync(string token, string scope, CancellationToken cancellationToken)
    {
        var (link, _) = await Read(token, scope, cancellationToken);
        return link is null ? Fail<IdentityAccessLinkInfo>() : OperationResultFactory.Success(new IdentityAccessLinkInfo(link.ExpiresAt));
    }

    private async Task<Error?> LimitAsync(Guid userId, string? clientKey, bool begin, CancellationToken ct)
    {
        var limiter = rateLimiters?.FirstOrDefault();
        if (limiter is null) return null;
        var settings = rateLimitOptions ?? new IdentityRateLimitOptions();
        if (!string.IsNullOrWhiteSpace(clientKey))
        {
            if (clientKey.Length > 256 || clientKey.Any(char.IsControl)) return Invalid();
            var client = await limiter.HitAsync(new RateLimitRequest(begin ? "totp.enrollment.client" : "verification.response.client", clientKey,
                begin ? settings.VerificationClientPermitLimit : settings.VerificationResponseClientPermitLimit,
                begin ? settings.VerificationClientWindow : settings.VerificationResponseClientWindow), ct);
            if (!client.IsAllowed) return IdentityRateLimitErrors.Exceeded(client.RetryAfter);
        }
        var account = await limiter.HitAsync(new RateLimitRequest(begin ? "totp.enrollment.account" : "verification.response.account", userId.ToString("N"),
            begin ? settings.VerificationAccountPermitLimit : settings.VerificationResponseAccountPermitLimit,
            begin ? settings.VerificationAccountWindow : settings.VerificationResponseAccountWindow), ct);
        return account.IsAllowed ? null : IdentityRateLimitErrors.Exceeded(account.RetryAfter);
    }

    public async Task<OperationResult<IdentityAccessLinkEnrollment>> BeginEnrollmentAsync(BeginIdentityAccessLinkEnrollmentCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (link, _) = await Read(command.Token, command.Scope, cancellationToken);
        if (link is null) return Fail<IdentityAccessLinkEnrollment>();
        var limited = await LimitAsync(link.UserId, command.ClientKey, true, cancellationToken);
        if (limited is not null) return OperationResultFactory.Fail<IdentityAccessLinkEnrollment>(limited);
        var secret = totp.CreateSecret(); var protectedSecret = protector.Protect(secret);
        if (string.IsNullOrWhiteSpace(protectedSecret) || protectedSecret.Length > TotpLimits.MaximumProtectedSecretLength) return Fail<IdentityAccessLinkEnrollment>();
        var now = DateTimeOffset.UtcNow; var expiry = now.Add(totpOptions.EnrollmentLifetime);
        if (expiry > link.ExpiresAt) expiry = link.ExpiresAt;
        var id = Guid.NewGuid();
        var result = await links.BeginEnrollmentAsync(link.Id, link.Version, id, protectedSecret, expiry, now, cancellationToken);
        return result.IsSuccess ? OperationResultFactory.Success(new IdentityAccessLinkEnrollment(id, secret, expiry))
            : OperationResultFactory.Fail<IdentityAccessLinkEnrollment>(result.Errors);
    }

    public async Task<OperationResult<CompletedIdentityAccessLink<TProfile>>> CompleteAsync(CompleteIdentityAccessLinkCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (link, user) = await Read(command.Token, command.Scope, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (link is null || user is null || link.EnrollmentId != command.EnrollmentId || link.EnrollmentExpiresAt is null || link.EnrollmentExpiresAt <= now
            || link.ProtectedSecret is null || string.IsNullOrWhiteSpace(command.Code) || command.Code.Length > TotpLimits.MaximumResponseLength
            || !protector.TryUnprotect(link.ProtectedSecret, out var secret)) return Fail<CompletedIdentityAccessLink<TProfile>>();
        var limited = await LimitAsync(user.Id, command.ClientKey, false, cancellationToken);
        if (limited is not null) return OperationResultFactory.Fail<CompletedIdentityAccessLink<TProfile>>(limited);
        // Reserve an attempt with CAS before checking the code, so parallel guesses
        // cannot all bypass the per-link limit.
        var attempt = await links.RecordFailureAsync(link.Id, link.Version, now, cancellationToken);
        if (!attempt.IsSuccess) return Fail<CompletedIdentityAccessLink<TProfile>>();
        if (!totp.TryMatchCounter(secret, command.Code, now, null, out var counter))
            return Fail<CompletedIdentityAccessLink<TProfile>>();
        link = link with { Version = link.Version + 1, FailedAttempts = link.FailedAttempts + 1 };
        var error = PasswordPolicy.ValidateNewPassword(command.NewPassword, passwordOptions);
        if (error is not null) return OperationResultFactory.Fail<CompletedIdentityAccessLink<TProfile>>(error);
        foreach (var validator in passwordValidators)
        {
            var validated = await validator.ValidateAsync(new PasswordValidationContext<TProfile>(user, command.NewPassword, PasswordMutation.Reset), cancellationToken);
            if (!validated.IsSuccess) return OperationResultFactory.Fail<CompletedIdentityAccessLink<TProfile>>(validated.Errors);
        }
        var codes = Enumerable.Range(0, totpOptions.RecoveryCodeCount).Select(_ => TotpRecoveryCodes.Create()).ToArray();
        var newStamp = stamps.Generate();
        var verifier = passwordHasher.HashPassword(command.NewPassword);
        now = DateTimeOffset.UtcNow;
        var completed = await links.CompleteAsync(link, verifier, counter,
            codes.Select(TotpRecoveryCodes.Hash).ToArray(), newStamp, now, cancellationToken);
        if (!completed.IsSuccess) return OperationResultFactory.Fail<CompletedIdentityAccessLink<TProfile>>(completed.Errors);
        securityEvents.Observe(IdentitySecurityEventTypes.AccessLinkUsed, now, user.Id, link.Id);
        return OperationResultFactory.Success(new CompletedIdentityAccessLink<TProfile>(
            user with { Version = user.Version + 1, SecurityStamp = newStamp, ModifiedAt = now }, codes));
    }
}
