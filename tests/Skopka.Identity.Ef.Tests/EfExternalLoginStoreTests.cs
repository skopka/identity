using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfExternalLoginStoreTests
{
    [Fact]
    public async Task LinkResolveListAndUnlinkPersistLifecycle()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync("alice");
        var login = new ExternalLoginKey("GOOGLE", "subject-1");
        var linkedAt = user.ModifiedAt.AddMinutes(1);

        var linked = await database.LoginStore.LinkAsync(
            user.Id,
            user.Version,
            login,
            "LINK-STAMP",
            linkedAt,
            CancellationToken.None);

        Assert.True(linked.IsSuccess);
        Assert.Equal(user.Version + 1, linked.Value.Version);
        Assert.Equal("LINK-STAMP", linked.Value.SecurityStamp);

        var resolved = await database.LoginStore.FindActiveUserAsync(
            login,
            CancellationToken.None);
        var listed = await database.LoginStore.ListAsync(
            user.Id,
            CancellationToken.None);

        Assert.Equal(linked.Value, resolved);
        var listedLogin = Assert.Single(listed);
        Assert.Equal(login, listedLogin.Login);
        Assert.Equal(linkedAt, listedLogin.CreatedAt);

        var unlinked = await database.LoginStore.UnlinkAsync(
            user.Id,
            linked.Value.Version,
            login,
            "UNLINK-STAMP",
            linkedAt.AddMinutes(1),
            CancellationToken.None);

        Assert.True(unlinked.IsSuccess);
        Assert.Equal(linked.Value.Version + 1, unlinked.Value.Version);
        Assert.Equal("UNLINK-STAMP", unlinked.Value.SecurityStamp);
        Assert.Null(
            await database.LoginStore.FindActiveUserAsync(
                login,
                CancellationToken.None));
    }

    [Fact]
    public async Task ExternalLoginCannotBeLinkedToTwoUsers()
    {
        await using var database = await TestDatabase.CreateAsync();
        var first = await database.CreateUserAsync("alice");
        var second = await database.CreateUserAsync("bob");
        var login = new ExternalLoginKey("GITHUB", "same-subject");

        var firstResult = await database.LoginStore.LinkAsync(
            first.Id,
            first.Version,
            login,
            "FIRST-STAMP",
            first.ModifiedAt.AddMinutes(1),
            CancellationToken.None);
        var secondResult = await database.LoginStore.LinkAsync(
            second.Id,
            second.Version,
            login,
            "SECOND-STAMP",
            second.ModifiedAt.AddMinutes(1),
            CancellationToken.None);

        Assert.True(firstResult.IsSuccess);
        AssertError(secondResult, IdentityErrorCodes.DuplicateExternalLogin);
    }

    [Fact]
    public async Task LinkRejectsStaleExpectedVersion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync("alice");

        var result = await database.LoginStore.LinkAsync(
            user.Id,
            user.Version + 1,
            new ExternalLoginKey("GOOGLE", "subject"),
            "STAMP",
            user.ModifiedAt.AddMinutes(1),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
        Assert.Empty(database.Context.ExternalLogins);
    }

    [Fact]
    public async Task ResolveExcludesDeletedUser()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync("alice");
        var login = new ExternalLoginKey("GOOGLE", "subject");
        var linked = await database.LoginStore.LinkAsync(
            user.Id,
            user.Version,
            login,
            "LINK-STAMP",
            user.ModifiedAt.AddMinutes(1),
            CancellationToken.None);
        Assert.True(linked.IsSuccess);

        var deleted = await database.UserStore.UpdateStateAsync(
            user.Id,
            linked.Value.Version,
            DateTimeOffset.UtcNow,
            null,
            null,
            "DELETE-STAMP",
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        Assert.True(deleted.IsSuccess);

        Assert.Null(
            await database.LoginStore.FindActiveUserAsync(
                login,
                CancellationToken.None));
    }

    private static void AssertError<T>(
        Skopka.Abstraction.OperationResult.OperationResult<T> result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfIdentityUserStore<TestProfile> userStore,
        EfExternalLoginStore<TestProfile> loginStore)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfIdentityUserStore<TestProfile> UserStore { get; } = userStore;
        public EfExternalLoginStore<TestProfile> LoginStore { get; } = loginStore;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            return new TestDatabase(
                context,
                new EfIdentityUserStore<TestProfile>(context),
                new EfExternalLoginStore<TestProfile>(context, []));
        }

        public async Task<IdentityUser<TestProfile>> CreateUserAsync(
            string userName)
        {
            var now = new DateTimeOffset(
                2026,
                7,
                30,
                12,
                0,
                0,
                TimeSpan.Zero);
            var result = await UserStore.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    userName,
                    $"{userName}@example.com",
                    null,
                    new TestProfile(userName),
                    UserFlags.None,
                    $"{userName}-STAMP"),
                new NormalizedHandles(
                    userName.ToUpperInvariant(),
                    $"{userName.ToUpperInvariant()}@EXAMPLE.COM",
                    null),
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
