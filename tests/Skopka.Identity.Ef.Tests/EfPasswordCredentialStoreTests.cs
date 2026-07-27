using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfPasswordCredentialStoreTests
{
    [Fact]
    public async Task SetPasswordVerifierCreatesCredentialAndBumpsUserVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var now = database.User.ModifiedAt.AddMinutes(1);

        var result = await database.CredentialStore.ReplacePasswordVerifierAsync(
            database.User.Id,
            database.User.Version,
            expectedPasswordVerifier: null,
            passwordVerifier: "opaque-verifier",
            newSecurityStamp: "NEW-STAMP",
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            "opaque-verifier",
            await database.CredentialStore.FindPasswordVerifierAsync(
                database.User.Id,
                CancellationToken.None));

        var user = await database.Context.Users
            .AsNoTracking()
            .SingleAsync(entity => entity.Id == database.User.Id);
        Assert.Equal(database.User.Version + 1, user.Version);
        Assert.Equal("NEW-STAMP", user.SecurityStamp);
        Assert.Equal(now, user.ModifiedAt);
    }

    [Fact]
    public async Task ReplacePasswordVerifierRequiresExpectedVerifier()
    {
        await using var database = await TestDatabase.CreateAsync("old-verifier");

        var result = await database.CredentialStore.ReplacePasswordVerifierAsync(
            database.User.Id,
            database.User.Version,
            expectedPasswordVerifier: "different-verifier",
            passwordVerifier: "new-verifier",
            newSecurityStamp: "NEW-STAMP",
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
        Assert.Equal(
            "old-verifier",
            await database.CredentialStore.FindPasswordVerifierAsync(
                database.User.Id,
                CancellationToken.None));
    }

    [Fact]
    public async Task ReplacePasswordVerifierChecksUserVersion()
    {
        await using var database = await TestDatabase.CreateAsync("old-verifier");

        var result = await database.CredentialStore.ReplacePasswordVerifierAsync(
            database.User.Id,
            database.User.Version + 1,
            expectedPasswordVerifier: "old-verifier",
            passwordVerifier: "new-verifier",
            newSecurityStamp: "NEW-STAMP",
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
    }

    [Fact]
    public async Task RemovePasswordVerifierKeepsCredentialRowAndClearsValue()
    {
        await using var database = await TestDatabase.CreateAsync("old-verifier");
        var now = database.User.ModifiedAt.AddMinutes(1);

        var result = await database.CredentialStore.ReplacePasswordVerifierAsync(
            database.User.Id,
            database.User.Version,
            expectedPasswordVerifier: "old-verifier",
            passwordVerifier: null,
            newSecurityStamp: "NEW-STAMP",
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);

        var credential = await database.Context.Credentials
            .AsNoTracking()
            .SingleAsync(entity => entity.UserId == database.User.Id);
        Assert.Null(credential.PasswordVerifier);
        Assert.Equal(now, credential.UpdatedAt);
    }

    [Fact]
    public async Task TechnicalRehashPreservesSecurityStamp()
    {
        await using var database = await TestDatabase.CreateAsync("old-verifier");

        var result = await database.CredentialStore.ReplacePasswordVerifierAsync(
            database.User.Id,
            database.User.Version,
            expectedPasswordVerifier: "old-verifier",
            passwordVerifier: "new-verifier",
            newSecurityStamp: null,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.True(result.IsSuccess);

        var user = await database.Context.Users
            .AsNoTracking()
            .SingleAsync(entity => entity.Id == database.User.Id);
        Assert.Equal(database.User.SecurityStamp, user.SecurityStamp);
    }

    private static void AssertError(
        Skopka.Abstraction.OperationResult.OperationResult result,
        string errorCode)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == errorCode);
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfPasswordCredentialStore<TestProfile> credentialStore,
        IdentityUser<TestProfile> user)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfPasswordCredentialStore<TestProfile> CredentialStore { get; } =
            credentialStore;
        public IdentityUser<TestProfile> User { get; } = user;

        public static async Task<TestDatabase> CreateAsync(
            string? passwordVerifier = null)
        {
            var options = new DbContextOptionsBuilder<IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            var userStore = new EfIdentityUserStore<TestProfile>(context);
            var now = new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero);
            var createResult = await userStore.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    "alice",
                    "alice@example.com",
                    null,
                    new TestProfile("Alice"),
                    UserFlags.None,
                    "OLD-STAMP"),
                new NormalizedHandles("ALICE", "ALICE@EXAMPLE.COM", null),
                now,
                CancellationToken.None);
            Assert.True(createResult.IsSuccess);

            var credentialStore = new EfPasswordCredentialStore<TestProfile>(context);
            if (passwordVerifier is not null)
            {
                var setResult = await credentialStore.ReplacePasswordVerifierAsync(
                    createResult.Value.Id,
                    createResult.Value.Version,
                    expectedPasswordVerifier: null,
                    passwordVerifier,
                    newSecurityStamp: "SET-STAMP",
                    now.AddMinutes(1),
                    CancellationToken.None);
                Assert.True(setResult.IsSuccess);

                var refreshedUser = await userStore.FindByIdAsync(
                    createResult.Value.Id,
                    CancellationToken.None);
                Assert.NotNull(refreshedUser);
                return new TestDatabase(context, credentialStore, refreshedUser);
            }

            return new TestDatabase(context, credentialStore, createResult.Value);
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
