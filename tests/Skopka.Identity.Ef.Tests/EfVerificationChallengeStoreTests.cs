using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfVerificationChallengeStoreTests
{
    [Fact]
    public async Task NewChallengeSupersedesExpiredPendingAndVerifiedSameIntent()
    {
        await using var database = await TestDatabase.CreateAsync();
        var first = await database.FindChallengeAsync();
        var secondId = Guid.NewGuid();

        var secondCreated = await database.Store.CreateAndSupersedeAsync(
            NewChallenge(
                secondId,
                first,
                database.Now.AddMinutes(15)),
            database.Now.AddMinutes(6),
            CancellationToken.None);

        Assert.True(secondCreated.IsSuccess);
        var supersededFirst = await database.FindChallengeAsync(first.Id);
        Assert.Equal(
            VerificationChallengeState.Superseded,
            supersededFirst.State);
        Assert.Equal(first.Version + 1, supersededFirst.Version);
        Assert.Equal(database.Now.AddMinutes(6), supersededFirst.ModifiedAt);

        const string proofHash =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var second = await database.FindChallengeAsync(secondId);
        var verified = await database.Store.RecordAttemptAsync(
            second.Id,
            second.Version,
            succeeded: true,
            proofHash,
            database.Now.AddMinutes(14),
            database.Now.AddMinutes(7),
            CancellationToken.None);
        Assert.True(verified.IsSuccess);

        var thirdId = Guid.NewGuid();
        var thirdCreated = await database.Store.CreateAndSupersedeAsync(
            NewChallenge(
                thirdId,
                verified.Value,
                database.Now.AddMinutes(20)),
            database.Now.AddMinutes(8),
            CancellationToken.None);

        Assert.True(thirdCreated.IsSuccess);
        var supersededSecond = await database.FindChallengeAsync(secondId);
        Assert.Equal(
            VerificationChallengeState.Superseded,
            supersededSecond.State);
        Assert.Equal(verified.Value.Version + 1, supersededSecond.Version);
        Assert.Equal(database.Now.AddMinutes(8), supersededSecond.ModifiedAt);
        Assert.Equal(
            VerificationChallengeState.Pending,
            (await database.FindChallengeAsync(thirdId)).State);
    }

    [Fact]
    public async Task DifferentIntentsRemainActiveTogether()
    {
        await using var database = await TestDatabase.CreateAsync();
        var first = await database.FindChallengeAsync();
        var secondId = Guid.NewGuid();

        var result = await database.Store.CreateAndSupersedeAsync(
            NewChallenge(
                secondId,
                first with { Binding = "different-resource" },
                database.Now.AddMinutes(10)),
            database.Now.AddMinutes(1),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            VerificationChallengeState.Pending,
            (await database.FindChallengeAsync(first.Id)).State);
        Assert.Equal(
            VerificationChallengeState.Pending,
            (await database.FindChallengeAsync(secondId)).State);
    }

    [Fact]
    public async Task ConcurrentInMemoryCreationLeavesOneActiveSameIntent()
    {
        var databaseName = Guid.NewGuid().ToString();
        var databaseRoot = new InMemoryDatabaseRoot();
        var options = new DbContextOptionsBuilder<
                IdentityDbContext<TestProfile>>()
            .UseInMemoryDatabase(databaseName, databaseRoot)
            .Options;
        var now = new DateTimeOffset(
            2026,
            8,
            3,
            12,
            0,
            0,
            TimeSpan.Zero);
        Guid userId;

        await using (var setupContext =
            new IdentityDbContext<TestProfile>(options))
        {
            var userStore = new EfIdentityUserStore<TestProfile>(setupContext);
            var created = await userStore.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    "concurrent",
                    null,
                    null,
                    new TestProfile("Concurrent"),
                    UserFlags.None,
                    "CONCURRENT-STAMP"),
                new NormalizedHandles("CONCURRENT", null, null),
                now,
                CancellationToken.None);
            Assert.True(created.IsSuccess);
            userId = created.Value.Id;
        }

        await using var firstContext =
            new IdentityDbContext<TestProfile>(options);
        await using var secondContext =
            new IdentityDbContext<TestProfile>(options);
        var firstStore = new EfVerificationChallengeStore<TestProfile>(
            firstContext);
        var secondStore = new EfVerificationChallengeStore<TestProfile>(
            secondContext);
        var start = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<Skopka.Abstraction.OperationResult.OperationResult> IssueAsync(
            EfVerificationChallengeStore<TestProfile> store,
            Guid challengeId)
        {
            await start.Task;
            return await store.CreateAndSupersedeAsync(
                new NewVerificationChallenge(
                    challengeId,
                    userId,
                    "password.change",
                    "same-binding",
                    VerificationMethods.OneTimeCode,
                    $"verifier-{challengeId:N}",
                    "CONCURRENT-STAMP",
                    5,
                    now.AddMinutes(5)),
                now,
                CancellationToken.None);
        }

        var firstTask = IssueAsync(firstStore, Guid.NewGuid());
        var secondTask = IssueAsync(secondStore, Guid.NewGuid());
        start.SetResult();
        var results = await Task.WhenAll(firstTask, secondTask);

        Assert.All(results, result => Assert.True(result.IsSuccess));
        await using var assertionContext =
            new IdentityDbContext<TestProfile>(options);
        var challenges = await assertionContext.VerificationChallenges
            .AsNoTracking()
            .Where(challenge => challenge.UserId == userId)
            .ToArrayAsync();
        Assert.Equal(2, challenges.Length);
        Assert.Single(
            challenges,
            challenge => challenge.State
                == VerificationChallengeState.Pending);
        Assert.Single(
            challenges,
            challenge => challenge.State
                == VerificationChallengeState.Superseded);
    }

    [Fact]
    public async Task FailedAttemptsLockChallengeAtLimit()
    {
        await using var database = await TestDatabase.CreateAsync(maxAttempts: 2);
        var challenge = await database.FindChallengeAsync();

        var first = await database.Store.RecordAttemptAsync(
            challenge.Id,
            challenge.Version,
            succeeded: false,
            proofHash: null,
            proofExpiresAt: null,
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(first.IsSuccess);

        var second = await database.Store.RecordAttemptAsync(
            challenge.Id,
            first.Value.Version,
            succeeded: false,
            proofHash: null,
            proofExpiresAt: null,
            database.Now.AddMinutes(2),
            CancellationToken.None);

        Assert.True(second.IsSuccess);
        Assert.Equal(2, second.Value.FailedAttemptCount);
        Assert.Equal(VerificationChallengeState.Locked, second.Value.State);
    }

    [Fact]
    public async Task VerifiedProofCanBeConsumedOnlyOnce()
    {
        await using var database = await TestDatabase.CreateAsync();
        var challenge = await database.FindChallengeAsync();
        const string proofHash =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var verified = await database.Store.RecordAttemptAsync(
            challenge.Id,
            challenge.Version,
            succeeded: true,
            proofHash,
            database.Now.AddMinutes(2),
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(verified.IsSuccess);

        var first = await database.Store.ConsumeProofAsync(
            challenge.Id,
            verified.Value.Version,
            challenge.UserId,
            challenge.Purpose,
            challenge.Binding,
            proofHash,
            challenge.SecurityStamp,
            database.Now.AddMinutes(1),
            CancellationToken.None);
        var replay = await database.Store.ConsumeProofAsync(
            challenge.Id,
            verified.Value.Version,
            challenge.UserId,
            challenge.Purpose,
            challenge.Binding,
            proofHash,
            challenge.SecurityStamp,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        Assert.True(first.IsSuccess);
        AssertError(replay, IdentityErrorCodes.VerificationProofInvalid);

        var stored = await database.FindChallengeAsync();
        Assert.Equal(VerificationChallengeState.Consumed, stored.State);
        Assert.NotNull(stored.ConsumedAt);
    }

    [Fact]
    public async Task ConsumptionChecksPurposeBindingAndStamp()
    {
        await using var database = await TestDatabase.CreateAsync();
        var challenge = await database.FindChallengeAsync();
        const string proofHash =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var verified = await database.Store.RecordAttemptAsync(
            challenge.Id,
            challenge.Version,
            succeeded: true,
            proofHash,
            database.Now.AddMinutes(2),
            database.Now.AddMinutes(1),
            CancellationToken.None);
        Assert.True(verified.IsSuccess);

        var result = await database.Store.ConsumeProofAsync(
            challenge.Id,
            verified.Value.Version,
            challenge.UserId,
            challenge.Purpose,
            "different-intent",
            proofHash,
            challenge.SecurityStamp,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Equal(
            VerificationChallengeState.Verified,
            (await database.FindChallengeAsync()).State);
    }

    [Fact]
    public async Task RecordAttemptChecksExpectedVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var challenge = await database.FindChallengeAsync();

        var result = await database.Store.RecordAttemptAsync(
            challenge.Id,
            challenge.Version + 1,
            succeeded: false,
            proofHash: null,
            proofExpiresAt: null,
            database.Now.AddMinutes(1),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
        Assert.Equal(
            0,
            (await database.FindChallengeAsync()).FailedAttemptCount);
    }

    private static void AssertError(
        Skopka.Abstraction.OperationResult.OperationResult result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private static NewVerificationChallenge NewChallenge(
        Guid id,
        StoredVerificationChallenge intent,
        DateTimeOffset expiresAt)
        => new(
            id,
            intent.UserId,
            intent.Purpose,
            intent.Binding,
            intent.Method,
            $"opaque-verifier-{id:N}",
            intent.SecurityStamp,
            intent.MaxAttempts,
            expiresAt);

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfVerificationChallengeStore<TestProfile> store,
        IdentityUser<TestProfile> user,
        Guid challengeId,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfVerificationChallengeStore<TestProfile> Store { get; } = store;
        public IdentityUser<TestProfile> User { get; } = user;
        public Guid ChallengeId { get; } = challengeId;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync(int maxAttempts = 5)
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            var userStore = new EfIdentityUserStore<TestProfile>(context);
            var now = new DateTimeOffset(
                2026,
                7,
                28,
                12,
                0,
                0,
                TimeSpan.Zero);
            var created = await userStore.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    "alice",
                    "alice@example.com",
                    null,
                    new TestProfile("Alice"),
                    UserFlags.None,
                    "CURRENT-STAMP"),
                new NormalizedHandles(
                    "ALICE",
                    "ALICE@EXAMPLE.COM",
                    null),
                now,
                CancellationToken.None);
            Assert.True(created.IsSuccess);

            var store = new EfVerificationChallengeStore<TestProfile>(context);
            var challengeId = Guid.NewGuid();
            var challengeResult = await store.CreateAndSupersedeAsync(
                new NewVerificationChallenge(
                    challengeId,
                    created.Value.Id,
                    "profile.delete",
                    "profile-7:v1",
                    VerificationMethods.OneTimeCode,
                    "opaque-verifier",
                    created.Value.SecurityStamp,
                    maxAttempts,
                    now.AddMinutes(5)),
                now,
                CancellationToken.None);
            Assert.True(challengeResult.IsSuccess);

            return new TestDatabase(
                context,
                store,
                created.Value,
                challengeId,
                now);
        }

        public Task<StoredVerificationChallenge> FindChallengeAsync()
            => FindChallengeAsync(ChallengeId);

        public async Task<StoredVerificationChallenge> FindChallengeAsync(
            Guid challengeId)
        {
            var challenge = await Store.FindByIdAsync(
                challengeId,
                CancellationToken.None);
            Assert.NotNull(challenge);
            return challenge;
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
