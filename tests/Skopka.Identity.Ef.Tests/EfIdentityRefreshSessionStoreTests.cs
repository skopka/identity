using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityRefreshSessionStoreTests
{
    [Fact]
    public async Task RotateConsumesCurrentTokenAndCreatesReplacement()
    {
        await using var database = await TestDatabase.CreateAsync();
        var current = await database.FindAsync(database.Initial.TokenId);
        var replacement = database.NewSession(
            Guid.NewGuid(),
            current.SessionId,
            current.ExpiresAt,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        var result = await database.Store.RotateAsync(
            current.TokenId,
            current.Version,
            current.TokenHash,
            replacement,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        var consumed = await database.FindAsync(current.TokenId);
        Assert.NotNull(consumed.RotatedAt);
        Assert.Equal(replacement.TokenId, consumed.ReplacedByTokenId);

        var active = await database.Store.FindActiveBySessionIdAsync(
            current.SessionId,
            current.UserId,
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.NotNull(active);
        Assert.Equal(replacement.TokenId, active.TokenId);
        Assert.Equal(current.ExpiresAt, active.ExpiresAt);
    }

    [Fact]
    public async Task ReusingRotatedTokenRevokesEveryTokenInSession()
    {
        await using var database = await TestDatabase.CreateAsync();
        var current = await database.FindAsync(database.Initial.TokenId);
        var replacement = database.NewSession(
            Guid.NewGuid(),
            current.SessionId,
            current.ExpiresAt,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        var rotated = await database.Store.RotateAsync(
            current.TokenId,
            current.Version,
            current.TokenHash,
            replacement,
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(rotated.IsSuccess);

        var replay = await database.Store.RotateAsync(
            current.TokenId,
            current.Version,
            current.TokenHash,
            replacement,
            database.Now.AddMinutes(2),
            CancellationToken.None);

        AssertError(replay, IdentityErrorCodes.RefreshTokenReuseDetected);
        var sessions = await database.Context.RefreshSessions
            .AsNoTracking()
            .Where(session => session.SessionId == current.SessionId)
            .ToListAsync();
        Assert.Equal(2, sessions.Count);
        Assert.All(sessions, session => Assert.NotNull(session.RevokedAt));
    }

    [Fact]
    public async Task RotateRejectsWrongTokenHashWithoutChangingSession()
    {
        await using var database = await TestDatabase.CreateAsync();
        var current = await database.FindAsync(database.Initial.TokenId);
        var replacement = database.NewSession(
            Guid.NewGuid(),
            current.SessionId,
            current.ExpiresAt,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        var result = await database.Store.RotateAsync(
            current.TokenId,
            current.Version,
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            replacement,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.RefreshTokenInvalid);
        Assert.Null((await database.FindAsync(current.TokenId)).RotatedAt);
        Assert.Single(database.Context.RefreshSessions);
    }

    [Fact]
    public async Task PruneRemovesOnlyRequestedExpiredBatch()
    {
        await using var database = await TestDatabase.CreateAsync(
            databaseNowOffset: TimeSpan.FromDays(-10));
        await database.Store.CreateAsync(
            database.NewSession(
                Guid.NewGuid(),
                Guid.NewGuid(),
                database.Now.AddDays(-8),
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            database.Now.AddDays(-9),
            CancellationToken.None);
        await database.Store.CreateAsync(
            database.NewSession(
                Guid.NewGuid(),
                Guid.NewGuid(),
                database.Now.AddDays(2),
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            database.Now,
            CancellationToken.None);

        var removed = await database.Store.PruneAsync(
            database.Now.AddDays(-5),
            maxCount: 1,
            CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Equal(2, await database.Context.RefreshSessions.CountAsync());
    }

    private static void AssertError(
        Skopka.Abstraction.OperationResult.OperationResult result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfIdentityRefreshSessionStore<TestProfile> store,
        NewRefreshSession initial,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfIdentityRefreshSessionStore<TestProfile> Store { get; } = store;
        public NewRefreshSession Initial { get; } = initial;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync(
            TimeSpan? databaseNowOffset = null)
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            var store = new EfIdentityRefreshSessionStore<TestProfile>(context);
            var now = DateTimeOffset.UtcNow;
            var initial = new NewRefreshSession(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "CURRENT-STAMP",
                now.Add(databaseNowOffset ?? TimeSpan.FromDays(10)));
            await store.CreateAsync(initial, now, CancellationToken.None);
            return new TestDatabase(context, store, initial, now);
        }

        public NewRefreshSession NewSession(
            Guid tokenId,
            Guid sessionId,
            DateTimeOffset expiresAt,
            string tokenHash)
            => new(
                tokenId,
                sessionId,
                Initial.UserId,
                tokenHash,
                Initial.SecurityStamp,
                expiresAt);

        public async Task<StoredRefreshSession> FindAsync(Guid tokenId)
            => Assert.IsType<StoredRefreshSession>(
                await Store.FindByTokenIdAsync(
                    tokenId,
                    CancellationToken.None));

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
