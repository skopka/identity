using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Security;
using Skopka.Identity.Users;

namespace Skopka.Identity.WebAuthn;

public sealed class IdentityWebAuthnService<TProfile>(
    IWebAuthnCredentialStore<TProfile> credentialStore,
    IIdentityUserStore<TProfile> userStore,
    IWebAuthnCeremonyVerifier verifier,
    ISecurityStampService<TProfile> securityStamps,
    WebAuthnOptions options,
    IdentityRateLimitOptions rateLimitOptions,
    IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters,
    IIdentityMetrics metrics)
    : IIdentityWebAuthnService<TProfile>
{
    private readonly IIdentityRateLimiter<TProfile>? rateLimiter =
        rateLimiters.FirstOrDefault();

    public async Task<OperationResult<IReadOnlyList<WebAuthnCredentialDescriptor>>>
        ListAsync(Guid userId, CancellationToken ct)
    {
        using var op = metrics.Begin("webauthn.list");
        if (userId == Guid.Empty)
        {
            return Fail<IReadOnlyList<WebAuthnCredentialDescriptor>>(
                op,
                Validation("userId", "UserId is required."));
        }

        var user = await userStore.FindByIdAsync(userId, ct);
        var userError = ValidateActiveUser(user, DateTimeOffset.UtcNow);
        if (userError is not null)
        {
            return Fail<IReadOnlyList<WebAuthnCredentialDescriptor>>(op, userError);
        }

        var credentials = await credentialStore.ListByUserIdAsync(userId, ct);
        op.Success();
        return OperationResultFactory.Success<
            IReadOnlyList<WebAuthnCredentialDescriptor>>(
                [.. credentials.Select(Describe)]);
    }

    public async Task<OperationResult<WebAuthnCredentialDescriptor>> RegisterAsync(
        RegisterWebAuthnCredentialCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("webauthn.register");
        ArgumentNullException.ThrowIfNull(command);
        var validation = ValidateRequest(command.UserId, command.ClientKey)
            ?? ValidateLabel(command.Label)
            ?? ValidateChallenge(command.Challenge);
        if (validation is not null)
        {
            return Fail<WebAuthnCredentialDescriptor>(op, validation);
        }

        var now = DateTimeOffset.UtcNow;
        var limited = await CheckRateLimitsAsync(
            command.UserId,
            command.ClientKey,
            ct);
        if (limited is not null)
        {
            return Fail<WebAuthnCredentialDescriptor>(op, limited);
        }

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<WebAuthnCredentialDescriptor>(op, userError);
        }

        var existing = await credentialStore.ListByUserIdAsync(command.UserId, ct);
        if (existing.Count >= options.MaximumCredentialsPerUser)
        {
            return Fail<WebAuthnCredentialDescriptor>(
                op,
                WebAuthnServiceErrors.TooManyCredentials(
                    options.MaximumCredentialsPerUser));
        }

        // Verified here rather than by the caller, so that nothing can persist
        // a key without having checked the ceremony that delivered it.
        var attested = verifier.ReadRegistration(
            command.ClientDataJson,
            command.AttestationObject,
            Expect(command.Challenge));
        if (!attested.IsSuccess)
        {
            return Finish<WebAuthnCredentialDescriptor>(op, attested);
        }

        var credential = new NewWebAuthnCredential(
            Guid.NewGuid(),
            command.UserId,
            attested.Value.CredentialId.ToArray(),
            attested.Value.PublicKey.ToArray(),
            attested.Value.Algorithm,
            attested.Value.SignatureCounter,
            attested.Value.AuthenticatorId,
            attested.Value.BackedUp,
            Trim(command.Label));
        var created = await credentialStore.CreateAsync(credential, now, ct);
        if (!created.IsSuccess)
        {
            return Finish<WebAuthnCredentialDescriptor>(op, created);
        }

        op.Success();
        return OperationResultFactory.Success(new WebAuthnCredentialDescriptor(
            credential.Id,
            credential.UserId,
            credential.Label,
            credential.BackedUp,
            now,
            null));
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> AuthenticateAsync(
        AuthenticateWebAuthnCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("webauthn.authenticate");
        ArgumentNullException.ThrowIfNull(command);
        if (ValidateChallenge(command.Challenge) is not null
            || command.CredentialId.Length
                is < WebAuthnLimits.MinimumCredentialIdLength
                or > WebAuthnLimits.MaximumCredentialIdLength)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                WebAuthnServiceErrors.AssertionRejected());
        }

        var now = DateTimeOffset.UtcNow;
        var limited = await CheckAssertionRateLimitsAsync(command.ClientKey, ct);
        if (limited is not null)
        {
            return Fail<IdentityUser<TProfile>>(op, limited);
        }

        var credential = await credentialStore.FindByCredentialIdAsync(
            command.CredentialId,
            ct);
        if (credential is null)
        {
            // The same answer as a bad signature: whether a credential id is
            // known is not something an unauthenticated caller may learn.
            return Fail<IdentityUser<TProfile>>(
                op,
                WebAuthnServiceErrors.AssertionRejected());
        }

        var user = await userStore.FindByIdAsync(credential.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail<IdentityUser<TProfile>>(op, userError);
        }

        var verified = verifier.VerifyAssertion(
            command.ClientDataJson,
            command.AuthenticatorData,
            command.Signature,
            new WebAuthnAssertionExpectation(
                options.RelyingPartyId,
                [.. options.Origins],
                command.Challenge,
                options.UserVerificationRequired,
                credential.PublicKey,
                credential.Algorithm,
                credential.SignatureCounter));
        if (!verified.IsSuccess)
        {
            return Finish<IdentityUser<TProfile>>(op, verified);
        }

        // Written after the signature was accepted, and a refusal here means
        // the row moved on — the same assertion arriving twice. Only one of
        // them may be a sign-in.
        var advanced = await credentialStore.TryAdvanceCounterAsync(
            credential.Id,
            credential.Version,
            verified.Value.SignatureCounter,
            now,
            ct);
        if (!advanced.IsSuccess)
        {
            return Finish<IdentityUser<TProfile>>(op, advanced);
        }

        if (!advanced.Value)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                WebAuthnServiceErrors.AssertionRejected());
        }

        op.Success();
        return OperationResultFactory.Success(user!);
    }

    public async Task<OperationResult> RemoveAsync(
        RemoveWebAuthnCredentialCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("webauthn.remove");
        ArgumentNullException.ThrowIfNull(command);
        if (command.UserId == Guid.Empty || command.CredentialId == Guid.Empty)
        {
            return Fail(op, Validation("credentialId", "CredentialId is required."));
        }

        var now = DateTimeOffset.UtcNow;
        var user = await userStore.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        if (user!.Version != command.ExpectedVersion)
        {
            return Fail(
                op,
                new Error(
                    IdentityErrorCodes.ConcurrencyConflict,
                    "Concurrency conflict.",
                    ErrorType.Conflict));
        }

        var removed = await credentialStore.RemoveAsync(
            command.UserId,
            command.CredentialId,
            ct);
        if (!removed.IsSuccess)
        {
            return Finish(op, removed);
        }

        // A credential that is gone must not be able to sign in through a
        // session issued before it went, which is what the stamp decides.
        var rotated = await securityStamps.RotateAsync(
            new RotateSecurityStampCommand(command.UserId, command.ExpectedVersion),
            ct);
        return rotated.IsSuccess ? Success(op) : Finish(op, rotated);
    }

    private WebAuthnCeremonyExpectation Expect(byte[] challenge)
        => new(
            options.RelyingPartyId,
            [.. options.Origins],
            challenge,
            options.UserVerificationRequired);

    private static WebAuthnCredentialDescriptor Describe(
        StoredWebAuthnCredential credential)
        => new(
            credential.Id,
            credential.UserId,
            credential.Label,
            credential.BackedUp,
            credential.CreatedAt,
            credential.LastUsedAt);

    private async Task<Error?> CheckRateLimitsAsync(
        Guid userId,
        string? clientKey,
        CancellationToken ct)
    {
        if (rateLimiter is null)
        {
            return null;
        }

        var account = await rateLimiter.HitAsync(
            new RateLimitRequest(
                "verification.account",
                userId.ToString("N"),
                rateLimitOptions.VerificationAccountPermitLimit,
                rateLimitOptions.VerificationAccountWindow),
            ct);
        return account.IsAllowed
            ? await CheckClientAsync(clientKey, ct)
            : IdentityRateLimitErrors.Exceeded(account.RetryAfter);
    }

    /// <summary>
    /// The client alone, because an assertion arrives before anyone is known:
    /// there is no account to throttle until the signature has been accepted.
    /// </summary>
    private Task<Error?> CheckAssertionRateLimitsAsync(
        string? clientKey,
        CancellationToken ct)
        => rateLimiter is null
            ? Task.FromResult<Error?>(null)
            : CheckClientAsync(clientKey, ct);

    private async Task<Error?> CheckClientAsync(
        string? clientKey,
        CancellationToken ct)
    {
        var normalized = NormalizeClientKey(clientKey);
        if (rateLimiter is null || normalized is null)
        {
            return null;
        }

        var client = await rateLimiter.HitAsync(
            new RateLimitRequest(
                "verification.response.client",
                normalized,
                rateLimitOptions.VerificationResponseClientPermitLimit,
                rateLimitOptions.VerificationResponseClientWindow),
            ct);
        return client.IsAllowed
            ? null
            : IdentityRateLimitErrors.Exceeded(client.RetryAfter);
    }

    private static Error? ValidateRequest(Guid userId, string? clientKey)
    {
        if (userId == Guid.Empty)
        {
            return Validation("userId", "UserId is required.");
        }

        return clientKey is { Length: > RateLimitLimits.MaximumClientKeyLength }
            ? Validation("clientKey", "ClientKey exceeds the supported length.")
            : null;
    }

    private static Error? ValidateChallenge(byte[]? challenge)
        => challenge is null
            || challenge.Length is < WebAuthnLimits.MinimumChallengeLength
                or > WebAuthnLimits.MaximumChallengeLength
                ? Validation("challenge", "Challenge is required.")
                : null;

    private static Error? ValidateLabel(string? label)
        => label is { Length: > WebAuthnLimits.MaximumLabelLength }
            ? Validation("label", "Label exceeds the supported length.")
            : null;

    private static string? Trim(string? label)
        => string.IsNullOrWhiteSpace(label) ? null : label.Trim();

    private static Error? ValidateActiveUser(
        IdentityUser<TProfile>? user,
        DateTimeOffset now)
    {
        if (user is null)
        {
            return new Error(
                IdentityErrorCodes.UserNotFound,
                "User not found.",
                ErrorType.NotFound);
        }

        if (user.DeletedAt is not null)
        {
            return new Error(
                IdentityErrorCodes.UserDeleted,
                "User is deleted.",
                ErrorType.Conflict);
        }

        return user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now)
                ? new Error(
                    IdentityErrorCodes.AuthenticationBlocked,
                    "Authentication is blocked.",
                    ErrorType.Forbidden)
                : null;
    }

    private static string? NormalizeClientKey(string? clientKey)
        => string.IsNullOrWhiteSpace(clientKey) ? null : clientKey.Trim();

    private static Error Validation(string field, string message)
        => new(
            IdentityErrorCodes.Validation,
            "Validation failed.",
            ErrorType.Validation,
            new ValidationDetails(
                new Dictionary<string, string[]> { [field] = [message] }));

    private static OperationResult<T> Fail<T>(IIdentityOpScope op, Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult Fail(IIdentityOpScope op, Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult Success(IIdentityOpScope op)
    {
        op.Success();
        return OperationResultFactory.Success();
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail<T>(result.Errors);
    }

    private static OperationResult Finish(IIdentityOpScope op, OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail(result.Errors);
    }
}
