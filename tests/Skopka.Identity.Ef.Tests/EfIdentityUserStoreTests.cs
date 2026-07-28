using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityUserStoreTests
{
    [Fact]
    public async Task CreateAndFindPersistCompleteUserAggregate()
    {
        await using var database = await TestDatabase.CreateAsync();
        var now = new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

        var result = await database.Store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                "Alice",
                "alice@example.com",
                "+123456789",
                new TestProfile("Alice Smith"),
                UserFlags.None,
                "SECURITY-STAMP"),
            new NormalizedHandles("ALICE", "ALICE@EXAMPLE.COM", "+123456789"),
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);

        var created = result.Value;
        var found = await database.Store.FindByIdAsync(created.Id, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(created, found);
        Assert.Equal(1, found.Version);
        Assert.Equal(now, found.CreatedAt);
        Assert.Equal(now, found.ModifiedAt);
    }

    [Fact]
    public async Task UpdateHandlesChangesDisplayAndNormalizedValues()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();
        var modifiedAt = created.ModifiedAt.AddMinutes(1);

        var result = await database.Store.UpdateHandlesAsync(
            created.Id,
            created.Version,
            new UpdatedHandles(
                "alice-2", "ALICE-2",
                "alice2@example.com", "ALICE2@EXAMPLE.COM", false,
                null, null, false),
            modifiedAt,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.Version);
        Assert.Equal("alice-2", result.Value.UserName);
        Assert.Equal("alice2@example.com", result.Value.Email);
        Assert.Null(result.Value.Phone);
        Assert.Equal(modifiedAt, result.Value.ModifiedAt);

        var authUser = await database.Context.Users
            .AsNoTracking()
            .SingleAsync(user => user.Id == created.Id, CancellationToken.None);

        Assert.Equal("ALICE-2", authUser.NormalizedUserName);
        Assert.Equal("ALICE2@EXAMPLE.COM", authUser.NormalizedEmail);
        Assert.Null(authUser.NormalizedPhone);
    }

    [Fact]
    public async Task UpdateProfileAndStateIncrementVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();
        var profileModifiedAt = created.ModifiedAt.AddMinutes(1);

        var profileResult = await database.Store.UpdateProfileAsync(
            created.Id,
            created.Version,
            new TestProfile("Updated"),
            profileModifiedAt,
            CancellationToken.None);

        Assert.True(profileResult.IsSuccess);
        Assert.Equal(new TestProfile("Updated"), profileResult.Value.Profile);
        Assert.Equal(2, profileResult.Value.Version);

        var blockedAt = profileModifiedAt.AddMinutes(1);
        var blockedUntil = blockedAt.AddHours(1);
        var stateResult = await database.Store.UpdateStateAsync(
            created.Id,
            profileResult.Value.Version,
            null,
            blockedAt,
            blockedUntil,
            newSecurityStamp: null,
            blockedAt,
            CancellationToken.None);

        Assert.True(stateResult.IsSuccess);

        var found = await database.Store.FindByIdAsync(created.Id, CancellationToken.None);
        Assert.NotNull(found);
        Assert.Equal(3, found.Version);
        Assert.Equal(blockedAt, found.BlockedAt);
        Assert.Equal(blockedUntil, found.BlockedUntil);
        Assert.Equal(blockedAt, found.ModifiedAt);
    }

    [Fact]
    public async Task UpdateSecurityStampIncrementsVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();
        var now = created.ModifiedAt.AddMinutes(1);

        var result = await database.Store.UpdateSecurityStampAsync(
            created.Id,
            created.Version,
            "NEW-SECURITY-STAMP",
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(created.Version + 1, result.Value.Version);
        Assert.Equal("NEW-SECURITY-STAMP", result.Value.SecurityStamp);
        Assert.Equal(now, result.Value.ModifiedAt);
    }

    [Fact]
    public async Task StaleExpectedVersionReturnsConcurrencyConflict()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();

        var result = await database.Store.UpdateProfileAsync(
            created.Id,
            created.Version + 1,
            new TestProfile("Ignored"),
            created.ModifiedAt.AddMinutes(1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.ConcurrencyConflict);
    }

    [Fact]
    public async Task MissingUserReturnsNotFound()
    {
        await using var database = await TestDatabase.CreateAsync();

        var result = await database.Store.UpdateStateAsync(
            Guid.NewGuid(),
            1,
            null,
            null,
            null,
            newSecurityStamp: null,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task FindsActiveUserByNormalizedUserNameAndEmail()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();

        var byUserName = await database.Store.FindActiveByNormalizedUserNameAsync(
            "ALICE",
            CancellationToken.None);
        var byEmail = await database.Store.FindActiveByNormalizedEmailAsync(
            "ALICE@EXAMPLE.COM",
            CancellationToken.None);

        Assert.Equal(created, byUserName);
        Assert.Equal(created, byEmail);
    }

    [Fact]
    public async Task NormalizedLoginLookupExcludesDeletedUser()
    {
        await using var database = await TestDatabase.CreateAsync();
        var created = await database.CreateUserAsync();

        var deleteResult = await database.Store.UpdateStateAsync(
            created.Id,
            created.Version,
            DateTimeOffset.UtcNow,
            created.BlockedAt,
            created.BlockedUntil,
            newSecurityStamp: "DELETE-STAMP",
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        Assert.True(deleteResult.IsSuccess);

        Assert.Null(
            await database.Store.FindActiveByNormalizedUserNameAsync(
                "ALICE",
                CancellationToken.None));
        Assert.Null(
            await database.Store.FindActiveByNormalizedEmailAsync(
                "ALICE@EXAMPLE.COM",
                CancellationToken.None));
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfIdentityUserStore<TestProfile> store) : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfIdentityUserStore<TestProfile> Store { get; } = store;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            return new TestDatabase(
                context,
                new EfIdentityUserStore<TestProfile>(context));
        }

        public async Task<IdentityUser<TestProfile>> CreateUserAsync()
        {
            var now = new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);
            var result = await Store.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    "alice",
                    "alice@example.com",
                    null,
                    new TestProfile("Alice"),
                    UserFlags.None,
                    "SECURITY-STAMP"),
                new NormalizedHandles("ALICE", "ALICE@EXAMPLE.COM", null),
                now,
                CancellationToken.None);

            Assert.True(result.IsSuccess);
            return result.Value;
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
        }
    }
}
