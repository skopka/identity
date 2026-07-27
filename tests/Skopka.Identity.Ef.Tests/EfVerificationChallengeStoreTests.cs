using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfVerificationChallengeStoreTests
{
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
            var challengeResult = await store.CreateAsync(
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

        public async Task<StoredVerificationChallenge> FindChallengeAsync()
        {
            var challenge = await Store.FindByIdAsync(
                ChallengeId,
                CancellationToken.None);
            Assert.NotNull(challenge);
            return challenge;
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
