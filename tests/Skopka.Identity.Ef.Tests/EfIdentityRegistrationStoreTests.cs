using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Registration;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityRegistrationStoreTests
{
    [Fact]
    public async Task PasswordRegistrationPersistsUserProfileAndCredentialAtomically()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = CreateUser();

        var result = await database.Store.CreateWithPasswordAsync(
            user,
            Handles,
            "PASSWORD-VERIFIER",
            Now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(user.Id, result.Value.Id);
        var credential = await database.Context.Credentials
            .AsNoTracking()
            .SingleAsync(CancellationToken.None);
        Assert.Equal(user.Id, credential.UserId);
        Assert.Equal("PASSWORD-VERIFIER", credential.PasswordVerifier);
        Assert.Empty(database.Context.ExternalLogins);
        Assert.Single(database.Context.Users);
        Assert.Single(database.Context.Profiles);
        Assert.Equal(2, database.Context.LoginIdentifiers.Count());
        Assert.All(
            database.Context.LoginIdentifiers,
            identifier => Assert.True(identifier.IsActive));
    }

    [Fact]
    public async Task ExternalRegistrationPersistsUserProfileAndLoginAtomically()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = CreateUser();
        var login = new ExternalLoginKey("GITHUB", "subject");

        var result = await database.Store.CreateWithExternalLoginAsync(
            user,
            Handles,
            login,
            Now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        var external = await database.Context.ExternalLogins
            .AsNoTracking()
            .SingleAsync(CancellationToken.None);
        Assert.Equal(user.Id, external.UserId);
        Assert.Equal(login.Provider, external.Provider);
        Assert.Equal(login.Subject, external.Subject);
        Assert.Empty(database.Context.Credentials);
        Assert.Single(database.Context.Users);
        Assert.Single(database.Context.Profiles);
        Assert.Equal(2, database.Context.LoginIdentifiers.Count());
    }

    [Fact]
    public async Task DuplicateExternalLoginDoesNotCreatePartialUser()
    {
        await using var database = await TestDatabase.CreateAsync();
        var login = new ExternalLoginKey("GITHUB", "subject");
        var first = await database.Store.CreateWithExternalLoginAsync(
            CreateUser(),
            Handles,
            login,
            Now,
            CancellationToken.None);
        Assert.True(first.IsSuccess);

        var second = await database.Store.CreateWithExternalLoginAsync(
            CreateUser(),
            new NormalizedHandles(
                "BOB",
                "BOB@EXAMPLE.COM",
                null,
                ["BOB", "BOB@EXAMPLE.COM"]),
            login,
            Now.AddMinutes(1),
            CancellationToken.None);

        Assert.False(second.IsSuccess);
        Assert.Contains(
            second.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateExternalLogin);
        Assert.Single(database.Context.Users);
        Assert.Single(database.Context.Profiles);
        Assert.Single(database.Context.ExternalLogins);
    }

    private static readonly DateTimeOffset Now = new(
        2026,
        7,
        30,
        12,
        0,
        0,
        TimeSpan.Zero);

    private static readonly NormalizedHandles Handles = new(
        "ALICE",
        "ALICE@EXAMPLE.COM",
        null,
        ["ALICE", "ALICE@EXAMPLE.COM"]);

    private static NewIdentityUser<TestProfile> CreateUser()
        => new(
            "alice",
            "alice@example.com",
            null,
            new TestProfile("Alice"),
            UserFlags.None,
            "SECURITY-STAMP",
            Guid.NewGuid());

    public sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfIdentityRegistrationStore<TestProfile> store)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfIdentityRegistrationStore<TestProfile> Store { get; } = store;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();
            return new TestDatabase(
                context,
                new EfIdentityRegistrationStore<TestProfile>(context, []));
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
        }
    }
}
