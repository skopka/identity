using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.WebAuthn;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfWebAuthnCredentialStoreTests
{
    [Fact]
    public async Task FindsACredentialByTheIdentifierAnAssertionCarries()
    {
        await using var database = await TestDatabase.CreateAsync();
        var credentialId = Bytes(0x11);
        var created = await database.Store.CreateAsync(
            Credential(database.UserId, credentialId),
            database.Now,
            CancellationToken.None);
        Assert.True(created.IsSuccess);

        var found = await database.Store.FindByCredentialIdAsync(
            credentialId,
            CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(database.UserId, found.UserId);
        Assert.Equal(WebAuthnAlgorithm.Es256, found.Algorithm);
        Assert.Null(found.LastUsedAt);
    }

    /// <summary>
    /// The identifier names one row in the whole table, not one per user: an
    /// assertion arrives with nothing else to look a user up by.
    /// </summary>
    [Fact]
    public async Task RefusesToRegisterOneAuthenticatorTwice()
    {
        await using var database = await TestDatabase.CreateAsync();
        var credentialId = Bytes(0x22);
        Assert.True((await database.Store.CreateAsync(
            Credential(database.UserId, credentialId),
            database.Now,
            CancellationToken.None)).IsSuccess);

        var again = await database.Store.CreateAsync(
            Credential(database.UserId, credentialId),
            database.Now,
            CancellationToken.None);

        Assert.Contains(
            again.Errors,
            error => error.Code
                == IdentityErrorCodes.WebAuthnCredentialAlreadyRegistered);
    }

    [Fact]
    public async Task RefusesACredentialForAUserThatIsNotThere()
    {
        await using var database = await TestDatabase.CreateAsync();

        var created = await database.Store.CreateAsync(
            Credential(Guid.NewGuid(), Bytes(0x33)),
            database.Now,
            CancellationToken.None);

        Assert.Contains(
            created.Errors,
            error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    /// <summary>
    /// One assertion writes the counter once. The second attempt reads the row
    /// it already moved, and answers no rather than writing an older value over
    /// a newer one.
    /// </summary>
    [Fact]
    public async Task WritesTheCounterOnceForOneAssertion()
    {
        await using var database = await TestDatabase.CreateAsync();
        var credentialId = Bytes(0x44);
        Assert.True((await database.Store.CreateAsync(
            Credential(database.UserId, credentialId),
            database.Now,
            CancellationToken.None)).IsSuccess);
        var stored = await database.Store.FindByCredentialIdAsync(
            credentialId,
            CancellationToken.None);
        Assert.NotNull(stored);

        var used = database.Now.AddMinutes(1);
        var first = await database.Store.TryAdvanceCounterAsync(
            stored.Id,
            stored.Version,
            9,
            used,
            CancellationToken.None);
        var second = await database.Store.TryAdvanceCounterAsync(
            stored.Id,
            stored.Version,
            9,
            used,
            CancellationToken.None);

        Assert.True(first.Value);
        Assert.False(second.Value);
        var after = await database.Store.FindByCredentialIdAsync(
            credentialId,
            CancellationToken.None);
        Assert.Equal(9, after!.SignatureCounter);
        Assert.Equal(used, after.LastUsedAt);
        Assert.Equal(stored.Version + 1, after.Version);
    }

    [Fact]
    public async Task RemovesOnlyTheOwnersOwnCredential()
    {
        await using var database = await TestDatabase.CreateAsync();
        var credentialId = Bytes(0x55);
        Assert.True((await database.Store.CreateAsync(
            Credential(database.UserId, credentialId),
            database.Now,
            CancellationToken.None)).IsSuccess);
        var stored = await database.Store.FindByCredentialIdAsync(
            credentialId,
            CancellationToken.None);
        Assert.NotNull(stored);

        var stranger = await database.Store.RemoveAsync(
            Guid.NewGuid(),
            stored.Id,
            CancellationToken.None);
        var owner = await database.Store.RemoveAsync(
            database.UserId,
            stored.Id,
            CancellationToken.None);

        Assert.Contains(
            stranger.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnCredentialNotFound);
        Assert.True(owner.IsSuccess);
        Assert.Empty(await database.Store.ListByUserIdAsync(
            database.UserId,
            CancellationToken.None));
    }

    private static byte[] Bytes(byte seed)
        => [.. Enumerable.Range(0, 32).Select(index => (byte)(seed + index))];

    private static NewWebAuthnCredential Credential(Guid userId, byte[] credentialId)
        => new(
            Guid.NewGuid(),
            userId,
            credentialId,
            Bytes(0xA0),
            WebAuthnAlgorithm.Es256,
            0,
            Guid.NewGuid(),
            BackedUp: false,
            Label: "Ключ на ноутбуке");

    private sealed record TestProfile(string DisplayName);

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfWebAuthnCredentialStore<TestProfile> store,
        Guid userId,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfWebAuthnCredentialStore<TestProfile> Store { get; } = store;
        public Guid UserId { get; } = userId;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();
            var now = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
            var user = await new EfIdentityUserStore<TestProfile>(context)
                .CreateAsync(
                    new NewIdentityUser<TestProfile>(
                        "alice",
                        "alice@example.test",
                        null,
                        new TestProfile("Alice"),
                        UserFlags.None,
                        "CURRENT-STAMP"),
                    new NormalizedHandles(
                        "ALICE",
                        "ALICE@EXAMPLE.TEST",
                        null),
                    now,
                    CancellationToken.None);
            Assert.True(user.IsSuccess);
            return new TestDatabase(
                context,
                new EfWebAuthnCredentialStore<TestProfile>(context),
                user.Value.Id,
                now);
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
