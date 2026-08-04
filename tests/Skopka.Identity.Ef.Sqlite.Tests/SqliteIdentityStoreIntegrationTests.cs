using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Errors;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Roles.Queries;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqliteIdentityStoreIntegrationTests
{
    [Fact]
    public async Task PackagedMigrationsAndStoresWorkAgainstRealSqlite()
    {
        await using var connection = new SqliteConnection(
            "Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();

        var services = new ServiceCollection();
        services
            .AddSkopkaIdentity<TestProfile>()
            .AddRoles()
            .UseSqlite(connection);
        await using var provider = services.BuildServiceProvider();

        await ApplyMigrationsAsync(provider);

        var now = new DateTimeOffset(
            2026,
            8,
            5,
            12,
            30,
            0,
            TimeSpan.FromHours(3));
        var alice = await CreateUserAsync(
            provider,
            "alice",
            "alice@example.com",
            "+15551234567",
            "ALICE",
            "ALICE@EXAMPLE.COM",
            "+15551234567",
            now);

        await AssertProfileRoundTripAsync(provider, alice);
        await AssertDuplicateEmailIsMappedAsync(provider, now);
        await AssertCrossHandleCollisionIsMappedAsync(provider, now);
        await AssertUtcOrderingAndCursorQueryAsync(provider, now);
        await AssertVerificationSupersessionAsync(provider, alice, now);
        await AssertRateLimitLifecycleAsync(provider, now);
        await AssertRefreshSessionLifecycleAsync(provider, alice, now);
        await AssertDatabaseConcurrencyAsync(provider, alice.Id, now);
        await AssertMigrationsAppliedAsync(provider);
    }

    private static async Task ApplyMigrationsAsync(ServiceProvider provider)
    {
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        await context.Database.MigrateAsync();
    }

    private static async Task<IdentityUser<TestProfile>> CreateUserAsync(
        ServiceProvider provider,
        string userName,
        string email,
        string phone,
        string normalizedUserName,
        string normalizedEmail,
        string normalizedPhone,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                userName,
                email,
                phone,
                new TestProfile(userName, ["admin", "support"]),
                UserFlags.None,
                $"STAMP-{Guid.NewGuid():N}"),
            new NormalizedHandles(
                normalizedUserName,
                normalizedEmail,
                normalizedPhone,
                [normalizedUserName, normalizedEmail, normalizedPhone]),
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        return result.Value;
    }

    private static async Task AssertProfileRoundTripAsync(
        ServiceProvider provider,
        IdentityUser<TestProfile> created)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var found = await store.FindByIdAsync(created.Id, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(created.Profile.DisplayName, found.Profile.DisplayName);
        Assert.Equal(created.Profile.Tags, found.Profile.Tags);
        Assert.Equal(created.SecurityStamp, found.SecurityStamp);
        Assert.Equal(created.CreatedAt, found.CreatedAt);
        Assert.Equal(TimeSpan.Zero, found.CreatedAt.Offset);
    }

    private static async Task AssertDuplicateEmailIsMappedAsync(
        ServiceProvider provider,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                "bob",
                "alice@example.com",
                null,
                new TestProfile("Bob", []),
                UserFlags.None,
                "STAMP-BOB"),
            new NormalizedHandles(
                "BOB",
                "ALICE@EXAMPLE.COM",
                null,
                ["BOB", "ALICE@EXAMPLE.COM"]),
            now.AddSeconds(1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateEmail);
    }

    private static async Task AssertCrossHandleCollisionIsMappedAsync(
        ServiceProvider provider,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                "charlie",
                "alice",
                null,
                new TestProfile("Charlie", []),
                UserFlags.None,
                "STAMP-CHARLIE"),
            new NormalizedHandles(
                "CHARLIE",
                "ALICE",
                null,
                ["CHARLIE", "ALICE"]),
            now.AddSeconds(2),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code
                == IdentityErrorCodes.DuplicateLoginIdentifier);
    }

    private static async Task AssertUtcOrderingAndCursorQueryAsync(
        ServiceProvider provider,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        var earlier = new DateTimeOffset(
            2026,
            8,
            5,
            10,
            0,
            0,
            TimeSpan.FromHours(3));
        var later = new DateTimeOffset(
            2026,
            8,
            5,
            8,
            0,
            0,
            TimeSpan.Zero);

        context.Roles.AddRange(
            CreateRole("Earlier", earlier),
            CreateRole("Later", later),
            CreateRole("Newest", now.AddHours(1)));
        await context.SaveChangesAsync();

        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityRoleQueryStore<TestProfile>>();
        var firstPage = await store.QueryAsync(
            new IdentityRoleStoreQuery(null, 2, null),
            CancellationToken.None);
        var secondPage = await store.QueryAsync(
            new IdentityRoleStoreQuery(null, 2, firstPage.NextCursor),
            CancellationToken.None);

        Assert.Equal(["Newest", "Later"], firstPage.Items.Select(role => role.Name));
        Assert.Equal("Earlier", Assert.Single(secondPage.Items).Name);
    }

    private static RoleEntity CreateRole(string name, DateTimeOffset createdAt)
        => new()
        {
            Id = Guid.NewGuid(),
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            Version = 1,
            CreatedAt = createdAt,
            ModifiedAt = createdAt,
        };

    private static async Task AssertVerificationSupersessionAsync(
        ServiceProvider provider,
        IdentityUser<TestProfile> user,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IVerificationChallengeStore<TestProfile>>();
        var first = new NewVerificationChallenge(
            Guid.NewGuid(),
            user.Id,
            "step-up",
            "binding",
            "otp",
            "verifier-1",
            user.SecurityStamp,
            3,
            now.AddMinutes(5));
        var second = first with
        {
            Id = Guid.NewGuid(),
            Verifier = "verifier-2"
        };

        Assert.True((await store.CreateAndSupersedeAsync(
            first,
            now,
            CancellationToken.None)).IsSuccess);
        Assert.True((await store.CreateAndSupersedeAsync(
            second,
            now.AddSeconds(1),
            CancellationToken.None)).IsSuccess);

        var storedFirst = await store.FindByIdAsync(
            first.Id,
            CancellationToken.None);
        var storedSecond = await store.FindByIdAsync(
            second.Id,
            CancellationToken.None);
        Assert.NotNull(storedFirst);
        Assert.Equal(VerificationChallengeState.Superseded, storedFirst.State);
        Assert.NotNull(storedSecond);
        Assert.Equal(VerificationChallengeState.Pending, storedSecond.State);
    }

    private static async Task AssertRateLimitLifecycleAsync(
        ServiceProvider provider,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IRateLimitBucketStore<TestProfile>>();
        var partition = new RateLimitPartition(
            "sqlite-test",
            new string('A', RateLimitLimits.KeyHashLength));

        Assert.True((await store.HitAsync(
            "sqlite.integration",
            [partition],
            2,
            TimeSpan.FromMinutes(1),
            null,
            now,
            CancellationToken.None)).IsAllowed);
        Assert.True((await store.HitAsync(
            "sqlite.integration",
            [partition],
            2,
            TimeSpan.FromMinutes(1),
            null,
            now.AddSeconds(1),
            CancellationToken.None)).IsAllowed);
        Assert.False((await store.HitAsync(
            "sqlite.integration",
            [partition],
            2,
            TimeSpan.FromMinutes(1),
            null,
            now.AddSeconds(2),
            CancellationToken.None)).IsAllowed);
        Assert.Equal(1, await store.PruneAsync(
            now.AddMinutes(2),
            10,
            CancellationToken.None));
    }

    private static async Task AssertRefreshSessionLifecycleAsync(
        ServiceProvider provider,
        IdentityUser<TestProfile> user,
        DateTimeOffset now)
    {
        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityRefreshSessionStore<TestProfile>>();
        var session = new NewRefreshSession(
            Guid.NewGuid(),
            Guid.NewGuid(),
            user.Id,
            new string('B', SessionLimits.TokenHashLength),
            user.SecurityStamp,
            now.AddHours(1),
            new IdentitySessionMetadata("web", "SQLite test"));

        Assert.True((await store.CreateAsync(
            session,
            now,
            CancellationToken.None)).IsSuccess);
        var active = await store.FindActiveBySessionIdAsync(
            session.SessionId,
            user.Id,
            now.AddMinutes(1),
            CancellationToken.None);
        Assert.NotNull(active);
        Assert.Single(await store.ListActiveAsync(
            user.Id,
            now.AddMinutes(1),
            CancellationToken.None));
        Assert.Equal(1, await store.RevokeUserSessionAsync(
            user.Id,
            session.SessionId,
            now.AddMinutes(2),
            CancellationToken.None));
    }

    private static async Task AssertDatabaseConcurrencyAsync(
        ServiceProvider provider,
        Guid userId,
        DateTimeOffset now)
    {
        await using var firstScope = provider.CreateAsyncScope();
        await using var secondScope = provider.CreateAsyncScope();
        var first = firstScope.ServiceProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        var second = secondScope.ServiceProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        var firstUser = await first.Users.SingleAsync(user => user.Id == userId);
        var secondUser = await second.Users.SingleAsync(user => user.Id == userId);

        firstUser.Version++;
        firstUser.ModifiedAt = now.AddMinutes(3);
        secondUser.Version++;
        secondUser.ModifiedAt = now.AddMinutes(4);
        await first.SaveChangesAsync();
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
            () => second.SaveChangesAsync());
    }

    private static async Task AssertMigrationsAppliedAsync(
        ServiceProvider provider)
    {
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            SqliteIdentityDbContext<TestProfile>>();
        Assert.Equal(
            context.Database.GetMigrations(),
            await context.Database.GetAppliedMigrationsAsync());
        Assert.False(context.Database.HasPendingModelChanges());
    }

    public sealed record TestProfile(
        string DisplayName,
        IReadOnlyList<string> Tags);
}
