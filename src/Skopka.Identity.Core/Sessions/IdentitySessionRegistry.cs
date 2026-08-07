using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public sealed class IdentitySessionRegistry<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IIdentitySessionStore<TProfile> sessionStore,
    IdentitySessionOptions options,
    IIdentityMetrics metrics,
    IIdentitySecurityEventObserver? securityEvents = null)
    : IIdentitySessionRegistry<TProfile>
{
    public async Task<OperationResult<IdentitySessionInfo>> RegisterAsync(
        RegisterIdentitySessionCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.register");
        ValidateOptions();

        if (command.UserId == Guid.Empty
            || string.IsNullOrWhiteSpace(command.SecurityStamp)
            || command.SecurityStamp.Length > SessionLimits.SecurityStampLength)
        {
            return Fail<IdentitySessionInfo>(
                op,
                AuthenticationErrors.InvalidCredentials());
        }

        var metadata = IdentitySessionMetadataNormalizer.Normalize(
            command.Metadata);
        if (metadata.Error is not null)
        {
            return Fail<IdentitySessionInfo>(op, metadata.Error);
        }

        var now = DateTimeOffset.UtcNow;
        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (!IsActive(user, now)
            || !FixedTimeEquals(user!.SecurityStamp, command.SecurityStamp))
        {
            return Fail<IdentitySessionInfo>(
                op,
                AuthenticationErrors.InvalidCredentials());
        }

        var session = new NewIdentitySession(
            Guid.NewGuid(),
            user.Id,
            user.SecurityStamp,
            now.Add(options.RefreshSessionLifetime),
            metadata.Value);
        var created = await sessionStore.CreateAsync(session, now, ct);
        if (!created.IsSuccess)
        {
            return Fail<IdentitySessionInfo>(op, created.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.SessionCreated,
            now,
            user.Id,
            session.SessionId);
        op.Success();
        return OperationResultFactory.Success(
            new IdentitySessionInfo(
                session.SessionId,
                session.UserId,
                session.Metadata ?? new IdentitySessionMetadata(),
                session.ExpiresAt,
                now,
                now));
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> ValidateAsync(
        ValidateIdentitySessionCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("session.validate");

        if (command.UserId == Guid.Empty || command.SessionId == Guid.Empty)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.SessionInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var session = await sessionStore.FindByIdAsync(
            command.SessionId,
            command.UserId,
            ct);
        if (session is null
            || session.RevokedAt is not null
            || session.ExpiresAt <= now)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.SessionInvalid());
        }

        var user = await userStore.FindByIdAsync(command.UserId, ct);
        if (!IsActive(user, now)
            || !FixedTimeEquals(user!.SecurityStamp, session.SecurityStamp))
        {
            await sessionStore.RevokeSessionAsync(
                session.SessionId,
                now,
                ct);
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentitySessionErrors.SessionInvalid());
        }

        op.Success();
        return OperationResultFactory.Success(user);
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

    private void ValidateOptions()
    {
        if (options.RefreshSessionLifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Session lifetime must be positive.");
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

    private static OperationResult Fail(IIdentityOpScope op, Error error)
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
