using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public sealed class IdentitySessionService<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IIdentityRefreshSessionStore<TProfile> sessionStore,
    IIdentityAccessTokenProvider accessTokenProvider,
    IIdentityRefreshTokenProvider refreshTokenProvider,
    IEnumerable<IIdentitySessionClaimsProvider<TProfile>> claimsProviders,
    IdentitySessionOptions options,
    IIdentityMetrics metrics,
    IIdentitySecurityEventObserver? securityEvents = null)
    : IIdentitySessionService<TProfile>
{
    internal const int CurrentAccessTokenFormatVersion = 1;

    public async Task<OperationResult<IssuedIdentitySession>> CreateAsync(
        CreateIdentitySessionCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.create");
        ValidateOptions();

        if (string.IsNullOrWhiteSpace(command.SecurityStamp)
            || command.SecurityStamp.Length > SessionLimits.SecurityStampLength)
        {
            return Fail<IssuedIdentitySession>(
                op,
                AuthenticationErrors.InvalidCredentials());
        }

        var metadata = NormalizeMetadata(command.Metadata);
        if (metadata.Error is not null)
        {
            return Fail<IssuedIdentitySession>(op, metadata.Error);
        }

        var now = DateTimeOffset.UtcNow;
        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (!IsActive(user, now)
            || !FixedTimeEquals(
                user!.SecurityStamp,
                command.SecurityStamp))
        {
            return Fail<IssuedIdentitySession>(
                op,
                AuthenticationErrors.InvalidCredentials());
        }

        var sessionId = Guid.NewGuid();
        var refreshTokenId = Guid.NewGuid();
        var refreshToken = refreshTokenProvider.Generate(refreshTokenId);
        var refreshExpiresAt = now.Add(options.RefreshSessionLifetime);
        var issued = await IssueTokensAsync(
            user,
            sessionId,
            refreshToken.Token,
            refreshExpiresAt,
            now,
            ct);
        var createResult = await sessionStore.CreateAsync(
            new NewRefreshSession(
                refreshTokenId,
                sessionId,
                user.Id,
                refreshToken.TokenHash,
                user.SecurityStamp,
                refreshExpiresAt,
                metadata.Value),
            now,
            ct);

        if (!createResult.IsSuccess)
        {
            return Fail<IssuedIdentitySession>(
                op,
                createResult.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.SessionCreated,
            now,
            user.Id,
            sessionId);
        op.Success();
        return OperationResultFactory.Success(issued);
    }

    public async Task<OperationResult<IssuedIdentitySession>> RefreshAsync(
        RefreshIdentitySessionCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.refresh");
        ValidateOptions();

        if (!TryReadRefreshToken(
                command.RefreshToken,
                out var tokenId,
                out var tokenHash))
        {
            return Fail<IssuedIdentitySession>(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var current = await sessionStore.FindByTokenIdAsync(tokenId, ct);
        if (current is null
            || !FixedTimeEquals(current.TokenHash, tokenHash))
        {
            return Fail<IssuedIdentitySession>(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        if (current.RotatedAt is not null)
        {
            await sessionStore.RevokeSessionAsync(
                current.SessionId,
                now,
                ct);
            return Fail<IssuedIdentitySession>(
                op,
                IdentitySessionErrors.RefreshTokenReuseDetected());
        }

        if (current.RevokedAt is not null || current.ExpiresAt <= now)
        {
            return Fail<IssuedIdentitySession>(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        var user = await userStore.FindByIdAsync(current.UserId, ct);
        if (!IsActive(user, now)
            || !FixedTimeEquals(
                user!.SecurityStamp,
                current.SecurityStamp))
        {
            await sessionStore.RevokeSessionAsync(
                current.SessionId,
                now,
                ct);
            return Fail<IssuedIdentitySession>(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        var replacementTokenId = Guid.NewGuid();
        var replacementToken = refreshTokenProvider.Generate(
            replacementTokenId);
        var replacement = new NewRefreshSession(
            replacementTokenId,
            current.SessionId,
            current.UserId,
            replacementToken.TokenHash,
            current.SecurityStamp,
            current.ExpiresAt,
            current.Metadata);
        var issued = await IssueTokensAsync(
            user,
            current.SessionId,
            replacementToken.Token,
            current.ExpiresAt,
            now,
            ct);

        var rotateResult = await sessionStore.RotateAsync(
            current.TokenId,
            current.Version,
            current.TokenHash,
            replacement,
            now,
            ct);
        if (rotateResult.Errors.Any(
                error => error.Code == IdentityErrorCodes.ConcurrencyConflict))
        {
            rotateResult = await sessionStore.RotateAsync(
                current.TokenId,
                current.Version,
                current.TokenHash,
                replacement,
                now,
                ct);
        }

        if (!rotateResult.IsSuccess)
        {
            return Fail<IssuedIdentitySession>(
                op,
                rotateResult.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.SessionRefreshed,
            now,
            current.UserId,
            current.SessionId);
        op.Success();
        return OperationResultFactory.Success(issued);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>>
        ValidateAccessTokenAsync(
            string accessToken,
            CancellationToken ct)
    {
        using var op = metrics.Begin("session.validate_access");

        if (string.IsNullOrWhiteSpace(accessToken)
            || accessToken.Length > SessionLimits.MaximumTokenLength)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.AccessTokenInvalid());
        }

        var payload = await accessTokenProvider.ValidateAsync(
            accessToken,
            ct);
        var now = DateTimeOffset.UtcNow;
        if (payload is null
            || payload.FormatVersion != CurrentAccessTokenFormatVersion)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.AccessTokenInvalid());
        }

        var session = await sessionStore.FindActiveBySessionIdAsync(
            payload.SessionId,
            payload.UserId,
            now,
            ct);
        if (session is null)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.AccessTokenInvalid());
        }

        var user = await userStore.FindByIdAsync(payload.UserId, ct);
        if (!IsActive(user, now)
            || !FixedTimeEquals(
                user!.SecurityStamp,
                session.SecurityStamp))
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.AccessTokenInvalid());
        }

        op.Success();
        return OperationResultFactory.Success(user);
    }

    public async Task<OperationResult> RevokeAsync(
        RevokeIdentitySessionCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.revoke");

        if (!TryReadRefreshToken(
                command.RefreshToken,
                out var tokenId,
                out var tokenHash))
        {
            return Fail(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        var session = await sessionStore.FindByTokenIdAsync(tokenId, ct);
        if (session is null
            || !FixedTimeEquals(session.TokenHash, tokenHash))
        {
            return Fail(
                op,
                IdentitySessionErrors.RefreshTokenInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var revoked = await sessionStore.RevokeSessionAsync(
            session.SessionId,
            now,
            ct);

        if (revoked > 0)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.SessionRevoked,
                now,
                session.UserId,
                session.SessionId);
        }
        op.Success();
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult> RevokeAllAsync(
        RevokeAllIdentitySessionsCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.revoke_all");

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        var now = DateTimeOffset.UtcNow;
        var revoked = await sessionStore.RevokeAllAsync(
            command.UserId,
            now,
            ct);

        if (revoked > 0)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.SessionsRevoked,
                now,
                command.UserId);
        }
        op.Success();
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult> RevokeByIdAsync(
        RevokeIdentitySessionByIdCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.revoke_by_id");

        if (command.UserId == Guid.Empty)
        {
            return Fail(
                op,
                IdentityErrors.Validation("userId", "UserId is required."));
        }

        if (command.SessionId == Guid.Empty)
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "sessionId",
                    "SessionId is required."));
        }

        var now = DateTimeOffset.UtcNow;
        var revoked = await sessionStore.RevokeUserSessionAsync(
            command.UserId,
            command.SessionId,
            now,
            ct);

        if (revoked > 0)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.SessionRevoked,
                now,
                command.UserId,
                command.SessionId);
        }
        op.Success();
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult<IReadOnlyList<IdentitySessionInfo>>> ListAsync(
        ListIdentitySessionsCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.list");

        if (command.UserId == Guid.Empty)
        {
            return Fail<IReadOnlyList<IdentitySessionInfo>>(
                op,
                IdentityErrors.Validation("userId", "UserId is required."));
        }

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (user is null)
        {
            return Fail<IReadOnlyList<IdentitySessionInfo>>(
                op,
                IdentityErrors.NotFound());
        }

        var sessions = await sessionStore.ListActiveAsync(
            command.UserId,
            DateTimeOffset.UtcNow,
            ct);

        op.Success();
        return OperationResultFactory.Success(sessions);
    }

    public async Task<int> PruneAsync(CancellationToken ct)
    {
        using var op = metrics.Begin("session.prune");
        ValidateOptions();

        var expiredBefore = DateTimeOffset.UtcNow.Subtract(
            options.RetentionAfterExpiration);
        var removed = await sessionStore.PruneAsync(
            expiredBefore,
            options.CleanupBatchSize,
            ct);

        op.Success();
        return removed;
    }

    private async Task<IssuedIdentitySession> IssueTokensAsync(
        IdentityUser<TProfile> user,
        Guid sessionId,
        string refreshToken,
        DateTimeOffset refreshExpiresAt,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var accessExpiresAt = Min(
            now.Add(options.AccessTokenLifetime),
            refreshExpiresAt);
        var claims = await GetClaimsAsync(user, ct);
        var accessToken = accessTokenProvider.Generate(
            new IdentityAccessTokenPayload(
                CurrentAccessTokenFormatVersion,
                Guid.NewGuid(),
                user.Id,
                sessionId,
                now,
                accessExpiresAt,
                claims));

        return new IssuedIdentitySession(
            sessionId,
            accessToken,
            accessExpiresAt,
            refreshToken,
            refreshExpiresAt);
    }

    private async Task<IReadOnlyList<IdentitySessionClaim>> GetClaimsAsync(
        IdentityUser<TProfile> user,
        CancellationToken ct)
    {
        var claims = new List<IdentitySessionClaim>();

        foreach (var provider in claimsProviders)
        {
            var projected = await provider.GetClaimsAsync(user, ct)
                ?? throw new InvalidOperationException(
                    "A session claims provider returned null.");
            claims.AddRange(projected);

            if (claims.Count > IdentitySessionClaimLimits.MaximumClaimCount)
            {
                throw new InvalidOperationException(
                    "Session claims exceed the supported count.");
            }
        }

        foreach (var claim in claims)
        {
            ValidateClaim(claim);
        }

        return claims;
    }

    private static void ValidateClaim(IdentitySessionClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        if (string.IsNullOrWhiteSpace(claim.Type)
            || claim.Type.Length
                > IdentitySessionClaimLimits.MaximumTypeLength)
        {
            throw new InvalidOperationException(
                "A session claim type is invalid.");
        }

        if (claim.Value is null
            || claim.Value.Length
                > IdentitySessionClaimLimits.MaximumValueLength)
        {
            throw new InvalidOperationException(
                "A session claim value is invalid.");
        }

        if (ReservedClaimTypes.Contains(claim.Type))
        {
            throw new InvalidOperationException(
                $"Session claim '{claim.Type}' is reserved.");
        }
    }

    private static readonly HashSet<string> ReservedClaimTypes =
        new(StringComparer.Ordinal)
        {
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sub",
            IdentitySessionClaimTypes.SessionId,
            IdentitySessionClaimTypes.FormatVersion,
        };

    private bool TryReadRefreshToken(
        string token,
        out Guid tokenId,
        out string tokenHash)
    {
        tokenId = default;
        tokenHash = string.Empty;

        if (string.IsNullOrWhiteSpace(token)
            || token.Length > SessionLimits.MaximumTokenLength
            || !refreshTokenProvider.TryRead(
                token,
                out tokenId,
                out var parsedTokenHash)
            || parsedTokenHash is null)
        {
            return false;
        }

        tokenHash = parsedTokenHash;
        return true;
    }

    private void ValidateOptions()
    {
        if (options.AccessTokenLifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Access token lifetime must be positive.");
        }

        if (options.RefreshSessionLifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Refresh session lifetime must be positive.");
        }

        if (options.RetentionAfterExpiration < TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Session retention cannot be negative.");
        }

        if (options.CleanupBatchSize <= 0)
        {
            throw new InvalidOperationException(
                "Session cleanup batch size must be positive.");
        }
    }

    private static bool IsActive(
        IdentityUser<TProfile>? user,
        DateTimeOffset now)
        => user is not null
            && user.DeletedAt is null
            && (user.BlockedAt is null
                || (user.BlockedUntil is not null
                    && user.BlockedUntil <= now));

    private static DateTimeOffset Min(
        DateTimeOffset first,
        DateTimeOffset second)
        => first <= second ? first : second;

    private static (IdentitySessionMetadata? Value, Error? Error)
        NormalizeMetadata(IdentitySessionMetadata? metadata)
    {
        if (metadata is null)
        {
            return (null, null);
        }

        var clientName = NormalizeLabel(metadata.ClientName);
        if (clientName?.Length > SessionLimits.MaximumClientNameLength)
        {
            return (
                null,
                IdentityErrors.Validation(
                    "metadata.clientName",
                    $"ClientName cannot exceed {SessionLimits.MaximumClientNameLength} characters."));
        }

        var deviceName = NormalizeLabel(metadata.DeviceName);
        if (deviceName?.Length > SessionLimits.MaximumDeviceNameLength)
        {
            return (
                null,
                IdentityErrors.Validation(
                    "metadata.deviceName",
                    $"DeviceName cannot exceed {SessionLimits.MaximumDeviceNameLength} characters."));
        }

        return (
            clientName is null && deviceName is null
                ? null
                : new IdentitySessionMetadata(clientName, deviceName),
            null);
    }

    private static string? NormalizeLabel(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool FixedTimeEquals(string expected, string provided)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);

        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expectedBytes,
                providedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(providedBytes);
        }
    }

    private static OperationResult Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        IReadOnlyCollection<Error> errors)
    {
        op.Failure(errors.First().Code);
        return OperationResultFactory.Fail<T>(errors);
    }
}
