using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentitySessionServiceTests
{
    [Fact]
    public async Task CreateBindsSessionToCurrentSecurityStamp()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.CreateAsync(
            new CreateIdentitySessionCommand(
                fixture.UserStore.User.Id,
                fixture.UserStore.User.SecurityStamp),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        var stored = Assert.Single(fixture.SessionStore.Sessions);
        Assert.Equal(fixture.UserStore.User.Id, stored.UserId);
        Assert.Equal(fixture.UserStore.User.SecurityStamp, stored.SecurityStamp);
        Assert.Equal(result.Value.SessionId, stored.SessionId);
        Assert.Equal(stored.ExpiresAt, result.Value.RefreshTokenExpiresAt);
        Assert.NotEqual(result.Value.RefreshToken, stored.TokenHash);
        Assert.Contains(
            fixture.AccessTokenProvider.LastGeneratedPayload!.Claims!,
            claim => claim.Type == IdentitySessionClaimTypes.Email
                && claim.Value == fixture.UserStore.User.Email);
    }

    [Fact]
    public async Task CreateRejectsStaleSecurityStamp()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.CreateAsync(
            new CreateIdentitySessionCommand(
                fixture.UserStore.User.Id,
                "STALE-STAMP"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
        Assert.Empty(fixture.SessionStore.Sessions);
    }

    [Fact]
    public async Task CreateNormalizesAndRefreshPreservesSessionMetadata()
    {
        var fixture = new Fixture();
        var created = await fixture.Service.CreateAsync(
            new CreateIdentitySessionCommand(
                fixture.UserStore.User.Id,
                fixture.UserStore.User.SecurityStamp,
                new IdentitySessionMetadata("  web  ", "  laptop  ")),
            CancellationToken.None);
        Assert.True(created.IsSuccess);

        var refreshed = await fixture.Service.RefreshAsync(
            new RefreshIdentitySessionCommand(created.Value.RefreshToken),
            CancellationToken.None);

        Assert.True(refreshed.IsSuccess);
        Assert.Equal(
            new IdentitySessionMetadata("web", "laptop"),
            fixture.SessionStore.Active.Metadata);
    }

    [Fact]
    public async Task AccessTokenCannotOutliveAbsoluteSession()
    {
        var fixture = new Fixture(
            accessTokenLifetime: TimeSpan.FromMinutes(10),
            refreshSessionLifetime: TimeSpan.FromMinutes(1));

        var created = await fixture.CreateAsync();

        Assert.Equal(
            created.RefreshTokenExpiresAt,
            created.AccessTokenExpiresAt);
    }

    [Fact]
    public async Task CustomClaimsProviderCanProjectRepeatedRoles()
    {
        var fixture = new Fixture(
            additionalClaimsProviders: [new RoleClaimsProvider()]);

        await fixture.CreateAsync();

        var claims = fixture.AccessTokenProvider
            .LastGeneratedPayload!
            .Claims!;
        Assert.Contains(
            claims,
            claim => claim is
            {
                Type: IdentitySessionClaimTypes.Role,
                Value: "admin",
            });
        Assert.Contains(
            claims,
            claim => claim is
            {
                Type: IdentitySessionClaimTypes.Role,
                Value: "auditor",
            });
    }

    [Fact]
    public async Task InvalidCustomClaimsDoNotPersistSession()
    {
        var fixture = new Fixture(
            additionalClaimsProviders: [new ReservedClaimsProvider()]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Service.CreateAsync(
                new CreateIdentitySessionCommand(
                    fixture.UserStore.User.Id,
                    fixture.UserStore.User.SecurityStamp),
                CancellationToken.None));

        Assert.Empty(fixture.SessionStore.Sessions);
    }

    [Fact]
    public async Task RefreshRotatesTokenWithoutExtendingAbsoluteSessionExpiry()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();

        var refreshed = await fixture.Service.RefreshAsync(
            new RefreshIdentitySessionCommand(created.RefreshToken),
            CancellationToken.None);

        Assert.True(refreshed.IsSuccess);
        Assert.Equal(created.SessionId, refreshed.Value.SessionId);
        Assert.Equal(
            created.RefreshTokenExpiresAt,
            refreshed.Value.RefreshTokenExpiresAt);
        Assert.NotEqual(created.RefreshToken, refreshed.Value.RefreshToken);
        Assert.Equal(2, fixture.SessionStore.Sessions.Count);
        Assert.NotNull(
            fixture.SessionStore.Sessions
                .Single(session => session.TokenId !=
                    fixture.SessionStore.Active.TokenId)
                .RotatedAt);
    }

    [Fact]
    public async Task ReusingRotatedRefreshTokenRevokesWholeSession()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        var refreshed = await fixture.Service.RefreshAsync(
            new RefreshIdentitySessionCommand(created.RefreshToken),
            CancellationToken.None);
        Assert.True(refreshed.IsSuccess);

        var replay = await fixture.Service.RefreshAsync(
            new RefreshIdentitySessionCommand(created.RefreshToken),
            CancellationToken.None);

        AssertError(replay, IdentityErrorCodes.RefreshTokenReuseDetected);
        Assert.All(
            fixture.SessionStore.Sessions,
            session => Assert.NotNull(session.RevokedAt));
    }

    [Fact]
    public async Task RefreshRejectsChangedStampAndRevokesSession()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        fixture.UserStore.User = fixture.UserStore.User with
        {
            SecurityStamp = "CHANGED-STAMP",
        };

        var result = await fixture.Service.RefreshAsync(
            new RefreshIdentitySessionCommand(created.RefreshToken),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.RefreshTokenInvalid);
        Assert.NotNull(Assert.Single(fixture.SessionStore.Sessions).RevokedAt);
    }

    [Fact]
    public async Task OnlineAccessValidationObservesSessionRevocation()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();

        var valid = await fixture.Service.ValidateAccessTokenAsync(
            created.AccessToken,
            CancellationToken.None);
        var revoked = await fixture.Service.RevokeAsync(
            new RevokeIdentitySessionCommand(created.RefreshToken),
            CancellationToken.None);
        var invalid = await fixture.Service.ValidateAccessTokenAsync(
            created.AccessToken,
            CancellationToken.None);

        Assert.True(valid.IsSuccess);
        Assert.True(revoked.IsSuccess);
        AssertError(invalid, IdentityErrorCodes.AccessTokenInvalid);
    }

    [Fact]
    public async Task ListAndRevokeByIdAreScopedToUser()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();

        var listed = await fixture.Service.ListAsync(
            new ListIdentitySessionsCommand(fixture.UserStore.User.Id),
            CancellationToken.None);
        Assert.True(listed.IsSuccess);
        Assert.Equal(created.SessionId, Assert.Single(listed.Value).SessionId);

        var wrongUser = await fixture.Service.RevokeByIdAsync(
            new RevokeIdentitySessionByIdCommand(
                Guid.NewGuid(),
                created.SessionId),
            CancellationToken.None);
        Assert.True(wrongUser.IsSuccess);
        Assert.Null(fixture.SessionStore.Active.RevokedAt);

        var revoked = await fixture.Service.RevokeByIdAsync(
            new RevokeIdentitySessionByIdCommand(
                fixture.UserStore.User.Id,
                created.SessionId),
            CancellationToken.None);
        Assert.True(revoked.IsSuccess);
        Assert.All(
            fixture.SessionStore.Sessions,
            session => Assert.NotNull(session.RevokedAt));
    }

    [Fact]
    public async Task SecurityEventsArePublishedOnlyForChangedSessions()
    {
        var observer = new RecordingSecurityEventObserver();
        var fixture = new Fixture(securityEvents: observer);
        var created = await fixture.CreateAsync();

        await fixture.Service.RevokeByIdAsync(
            new RevokeIdentitySessionByIdCommand(
                Guid.NewGuid(),
                created.SessionId),
            CancellationToken.None);
        Assert.Single(
            observer.Events,
            item => item.Type == IdentitySecurityEventTypes.SessionCreated);
        Assert.DoesNotContain(
            observer.Events,
            item => item.Type == IdentitySecurityEventTypes.SessionRevoked);

        await fixture.Service.RevokeByIdAsync(
            new RevokeIdentitySessionByIdCommand(
                fixture.UserStore.User.Id,
                created.SessionId),
            CancellationToken.None);
        var revoked = Assert.Single(
            observer.Events,
            item => item.Type == IdentitySecurityEventTypes.SessionRevoked);
        Assert.Equal(fixture.UserStore.User.Id, revoked.UserId);
        Assert.Equal(created.SessionId, revoked.ResourceId);
    }

    private static void AssertError(OperationResult result, string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class Fixture
    {
        public Fixture(
            TimeSpan? accessTokenLifetime = null,
            TimeSpan? refreshSessionLifetime = null,
            IEnumerable<IIdentitySessionClaimsProvider<TestProfile>>?
                additionalClaimsProviders = null,
            IIdentitySecurityEventObserver? securityEvents = null)
        {
            UserStore = new FakeUserStore(CreateUser());
            SessionStore = new FakeSessionStore();
            AccessTokenProvider = new FakeAccessTokenProvider();
            RefreshTokenProvider = new FakeRefreshTokenProvider();
            var claimsProviders =
                new List<IIdentitySessionClaimsProvider<TestProfile>>
                {
                    new DefaultIdentitySessionClaimsProvider<TestProfile>(),
                };
            if (additionalClaimsProviders is not null)
            {
                claimsProviders.AddRange(additionalClaimsProviders);
            }

            Service = new IdentitySessionService<TestProfile>(
                UserStore,
                SessionStore,
                AccessTokenProvider,
                RefreshTokenProvider,
                claimsProviders,
                new IdentitySessionOptions
                {
                    AccessTokenLifetime = accessTokenLifetime
                        ?? TimeSpan.FromMinutes(5),
                    RefreshSessionLifetime = refreshSessionLifetime
                        ?? TimeSpan.FromDays(10),
                },
                new NoopIdentityMetrics(),
                securityEvents);
        }

        public FakeUserStore UserStore { get; }
        public FakeSessionStore SessionStore { get; }
        public FakeAccessTokenProvider AccessTokenProvider { get; }
        public FakeRefreshTokenProvider RefreshTokenProvider { get; }
        public IdentitySessionService<TestProfile> Service { get; }

        public async Task<IssuedIdentitySession> CreateAsync()
        {
            var result = await Service.CreateAsync(
                new CreateIdentitySessionCommand(
                    UserStore.User.Id,
                    UserStore.User.SecurityStamp),
                CancellationToken.None);
            Assert.True(result.IsSuccess);
            return result.Value;
        }
    }

    private sealed class FakeAccessTokenProvider
        : IIdentityAccessTokenProvider
    {
        private readonly Dictionary<string, IdentityAccessTokenPayload> tokens = [];

        public IdentityAccessTokenPayload? LastGeneratedPayload { get; private set; }

        public string Generate(IdentityAccessTokenPayload payload)
        {
            LastGeneratedPayload = payload;
            var token = $"access-{tokens.Count + 1}";
            tokens.Add(token, payload);
            return token;
        }

        public Task<IdentityAccessTokenPayload?> ValidateAsync(
            string token,
            CancellationToken ct)
            => Task.FromResult(
                tokens.TryGetValue(token, out var payload)
                    ? payload
                    : null);
    }

    private sealed class RecordingSecurityEventObserver
        : IIdentitySecurityEventObserver
    {
        public List<IdentitySecurityEvent> Events { get; } = [];

        public void OnEvent(IdentitySecurityEvent securityEvent)
            => Events.Add(securityEvent);
    }

    private sealed class RoleClaimsProvider
        : IIdentitySessionClaimsProvider<TestProfile>
    {
        public Task<IReadOnlyCollection<IdentitySessionClaim>>
            GetClaimsAsync(
                IdentityUser<TestProfile> user,
                CancellationToken ct)
            => Task.FromResult<IReadOnlyCollection<IdentitySessionClaim>>(
                [
                    new(IdentitySessionClaimTypes.Role, "admin"),
                    new(IdentitySessionClaimTypes.Role, "auditor"),
                ]);
    }

    private sealed class ReservedClaimsProvider
        : IIdentitySessionClaimsProvider<TestProfile>
    {
        public Task<IReadOnlyCollection<IdentitySessionClaim>>
            GetClaimsAsync(
                IdentityUser<TestProfile> user,
                CancellationToken ct)
            => Task.FromResult<IReadOnlyCollection<IdentitySessionClaim>>(
                [new("sub", "forged-user")]);
    }

    private sealed class FakeRefreshTokenProvider
        : IIdentityRefreshTokenProvider
    {
        public GeneratedRefreshToken Generate(Guid tokenId)
        {
            var token = $"refresh-{tokenId:N}";
            return new GeneratedRefreshToken(token, $"hash-{tokenId:N}");
        }

        public bool TryRead(
            string token,
            out Guid tokenId,
            out string? tokenHash)
        {
            tokenId = default;
            tokenHash = null;

            if (!token.StartsWith("refresh-", StringComparison.Ordinal)
                || !Guid.TryParseExact(token[8..], "N", out tokenId))
            {
                return false;
            }

            tokenHash = $"hash-{tokenId:N}";
            return true;
        }
    }

    private sealed class FakeSessionStore
        : IIdentityRefreshSessionStore<TestProfile>
    {
        public List<StoredRefreshSession> Sessions { get; } = [];

        public StoredRefreshSession Active
            => Sessions.Single(session =>
                session.RotatedAt is null
                && session.RevokedAt is null);

        public Task<StoredRefreshSession?> FindByTokenIdAsync(
            Guid tokenId,
            CancellationToken ct)
            => Task.FromResult(
                Sessions.SingleOrDefault(
                    session => session.TokenId == tokenId));

        public Task<StoredRefreshSession?> FindActiveBySessionIdAsync(
            Guid sessionId,
            Guid userId,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(
                Sessions.SingleOrDefault(session =>
                    session.SessionId == sessionId
                    && session.UserId == userId
                    && session.RotatedAt is null
                    && session.RevokedAt is null
                    && session.ExpiresAt > now));

        public Task<OperationResult> CreateAsync(
            NewRefreshSession session,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Sessions.Add(Map(session, now));
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult> RotateAsync(
            Guid tokenId,
            long expectedVersion,
            string expectedTokenHash,
            NewRefreshSession replacement,
            DateTimeOffset now,
            CancellationToken ct)
        {
            var index = Sessions.FindIndex(
                session => session.TokenId == tokenId);
            if (index < 0)
            {
                return Task.FromResult(
                    Fail(IdentityErrorCodes.RefreshTokenInvalid));
            }

            var current = Sessions[index];
            if (current.RotatedAt is not null)
            {
                Revoke(current.SessionId, now);
                return Task.FromResult(
                    Fail(IdentityErrorCodes.RefreshTokenReuseDetected));
            }

            Sessions[index] = current with
            {
                RotatedAt = now,
                ReplacedByTokenId = replacement.TokenId,
                ModifiedAt = now,
                Version = current.Version + 1,
            };
            Sessions.Add(Map(replacement, now));
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<int> RevokeSessionAsync(
            Guid sessionId,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(Revoke(sessionId, now));

        public Task<int> RevokeUserSessionAsync(
            Guid userId,
            Guid sessionId,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(
                Sessions.Any(session =>
                    session.UserId == userId
                    && session.SessionId == sessionId)
                    ? Revoke(sessionId, now)
                    : 0);

        public Task<int> RevokeAllAsync(
            Guid userId,
            DateTimeOffset now,
            CancellationToken ct)
        {
            var sessionIds = Sessions
                .Where(session => session.UserId == userId)
                .Select(session => session.SessionId)
                .Distinct()
                .ToArray();
            var count = sessionIds.Sum(sessionId => Revoke(sessionId, now));
            return Task.FromResult(count);
        }

        public Task<IReadOnlyList<IdentitySessionInfo>> ListActiveAsync(
            Guid userId,
            DateTimeOffset now,
            CancellationToken ct)
        {
            var sessions = Sessions
                .Where(session =>
                    session.UserId == userId
                    && session.RotatedAt is null
                    && session.RevokedAt is null
                    && session.ExpiresAt > now)
                .Select(session => new IdentitySessionInfo(
                    session.SessionId,
                    session.UserId,
                    session.Metadata ?? new IdentitySessionMetadata(),
                    session.ExpiresAt,
                    Sessions
                        .Where(item => item.SessionId == session.SessionId)
                        .Min(item => item.CreatedAt),
                    session.CreatedAt))
                .ToArray();
            return Task.FromResult<IReadOnlyList<IdentitySessionInfo>>(sessions);
        }

        public Task<int> PruneAsync(
            DateTimeOffset expiredBefore,
            int maxCount,
            CancellationToken ct)
        {
            var removed = Sessions
                .Where(session => session.ExpiresAt < expiredBefore)
                .Take(maxCount)
                .ToArray();
            foreach (var session in removed)
            {
                Sessions.Remove(session);
            }

            return Task.FromResult(removed.Length);
        }

        private int Revoke(Guid sessionId, DateTimeOffset now)
        {
            var count = 0;
            for (var index = 0; index < Sessions.Count; index++)
            {
                var session = Sessions[index];
                if (session.SessionId != sessionId
                    || session.RevokedAt is not null)
                {
                    continue;
                }

                Sessions[index] = session with
                {
                    RevokedAt = now,
                    ModifiedAt = now,
                    Version = session.Version + 1,
                };
                count++;
            }

            return count;
        }

        private static StoredRefreshSession Map(
            NewRefreshSession session,
            DateTimeOffset now)
            => new(
                session.TokenId,
                session.SessionId,
                session.UserId,
                session.TokenHash,
                session.SecurityStamp,
                1,
                session.ExpiresAt,
                now,
                now,
                null,
                null,
                null,
                session.Metadata);

        private static OperationResult Fail(string code)
            => OperationResultFactory.Fail(
                new Error(code, code, ErrorType.Unauthorized));
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; set; } = user;

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> newUser,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateHandlesAsync(
            Guid userId,
            long expectedVersion,
            UpdatedHandles updated,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(
            Guid userId,
            long expectedVersion,
            TestProfile profile,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateSecurityStampAsync(
                Guid userId,
                long expectedVersion,
                string securityStamp,
                DateTimeOffset now,
                CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    private static IdentityUser<TestProfile> CreateUser()
        => new(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            true,
            null,
            false,
            new TestProfile("Alice"),
            1,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    public sealed record TestProfile(string DisplayName);
}
