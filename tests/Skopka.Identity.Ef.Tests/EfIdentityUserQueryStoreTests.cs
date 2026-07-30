using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Queries;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityUserQueryStoreTests
{
    [Fact]
    public async Task QueryFiltersActiveBlockedAndDeletedUsers()
    {
        await using var database = CreateDatabase();
        var now = DateTimeOffset.UtcNow;
        AddUser(database.Context, "active", now.AddMinutes(-5));
        AddUser(
            database.Context,
            "expired-block",
            now.AddMinutes(-4),
            blockedAt: now.AddDays(-2),
            blockedUntil: now.AddDays(-1));
        AddUser(
            database.Context,
            "blocked",
            now.AddMinutes(-3),
            blockedAt: now.AddDays(-1));
        AddUser(
            database.Context,
            "temporarily-blocked",
            now.AddMinutes(-2),
            blockedAt: now.AddMinutes(-1),
            blockedUntil: now.AddDays(1));
        AddUser(
            database.Context,
            "deleted",
            now.AddMinutes(-1),
            deletedAt: now);
        await database.Context.SaveChangesAsync();

        var active = await database.QueryAsync(
            StatusQuery(IdentityUserStatus.Active),
            now);
        var blocked = await database.QueryAsync(
            StatusQuery(IdentityUserStatus.Blocked),
            now);
        var deleted = await database.QueryAsync(
            StatusQuery(IdentityUserStatus.Deleted),
            now);

        Assert.Equal(
            ["expired-block", "active"],
            active.Items.Select(user => user.UserName));
        Assert.Equal(
            ["temporarily-blocked", "blocked"],
            blocked.Items.Select(user => user.UserName));
        Assert.Equal("deleted", Assert.Single(deleted.Items).UserName);
    }

    [Fact]
    public async Task QueryCursorDoesNotSkipUsersWithSameCreatedAt()
    {
        await using var database = CreateDatabase();
        var createdAt = DateTimeOffset.UtcNow;
        AddUser(
            database.Context,
            "first",
            createdAt,
            Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        AddUser(
            database.Context,
            "second",
            createdAt,
            Guid.Parse("88888888-8888-8888-8888-888888888888"));
        AddUser(
            database.Context,
            "third",
            createdAt,
            Guid.Parse("11111111-1111-1111-1111-111111111111"));
        await database.Context.SaveChangesAsync();

        var firstPage = await database.QueryAsync(
            StatusQuery(IdentityUserStatus.Any, pageSize: 2),
            createdAt.AddMinutes(1));
        var secondPage = await database.QueryAsync(
            StatusQuery(
                IdentityUserStatus.Any,
                pageSize: 2,
                cursor: firstPage.NextCursor),
            createdAt.AddMinutes(1));

        Assert.Equal(2, firstPage.Items.Count);
        Assert.NotNull(firstPage.NextCursor);
        Assert.Single(secondPage.Items);
        Assert.Null(secondPage.NextCursor);
        Assert.Equal(
            3,
            firstPage.Items.Concat(secondPage.Items)
                .Select(user => user.Id)
                .Distinct()
                .Count());
    }

    [Fact]
    public async Task QuerySearchAndFlagsAreAppliedTogether()
    {
        await using var database = CreateDatabase();
        var now = DateTimeOffset.UtcNow;
        AddUser(
            database.Context,
            "alice-admin",
            now,
            flags: UserFlags.Protected,
            normalizedEmail: "ALICE@EXAMPLE.COM");
        AddUser(
            database.Context,
            "alice",
            now.AddMinutes(-1),
            normalizedEmail: "ALICE2@EXAMPLE.COM");
        await database.Context.SaveChangesAsync();

        var page = await database.QueryAsync(
            new IdentityUserStoreQuery(
                "ALICE",
                "ALICE",
                null,
                null,
                IdentityUserStatus.Any,
                UserFlags.Protected,
                10,
                null),
            now.AddMinutes(1));

        Assert.Equal("alice-admin", Assert.Single(page.Items).UserName);
    }

    private static IdentityUserStoreQuery StatusQuery(
        IdentityUserStatus status,
        int pageSize = 10,
        IdentityUserCursor? cursor = null)
        => new(
            null,
            null,
            null,
            null,
            status,
            UserFlags.None,
            pageSize,
            cursor);

    private static TestDatabase CreateDatabase()
    {
        var options = new DbContextOptionsBuilder<
                IdentityDbContext<TestProfile>>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;
        var context = new IdentityDbContext<TestProfile>(options);
        return new TestDatabase(
            context,
            new EfIdentityUserQueryStore<TestProfile>(context));
    }

    private static void AddUser(
        IdentityDbContext<TestProfile> context,
        string userName,
        DateTimeOffset createdAt,
        Guid? id = null,
        UserFlags flags = UserFlags.None,
        string? normalizedEmail = null,
        DateTimeOffset? deletedAt = null,
        DateTimeOffset? blockedAt = null,
        DateTimeOffset? blockedUntil = null)
    {
        var profile = new UserProfileEntity<TestProfile>
        {
            UserId = id ?? Guid.NewGuid(),
            UserName = userName,
            Email = normalizedEmail?.ToLowerInvariant(),
            Profile = new TestProfile(userName),
        };
        var user = new AuthUserEntity
        {
            Id = profile.UserId,
            Flags = (int)flags,
            NormalizedUserName = userName.ToUpperInvariant(),
            NormalizedEmail = normalizedEmail,
            Version = 1,
            SecurityStamp = new string('A', 64),
            DeletedAt = deletedAt,
            BlockedAt = blockedAt,
            BlockedUntil = blockedUntil,
            CreatedAt = createdAt,
            ModifiedAt = createdAt,
            Profile = profile,
        };
        profile.User = user;
        context.Users.Add(user);
    }

    private sealed class TestDatabase(
        IdentityDbContext<TestProfile> context,
        EfIdentityUserQueryStore<TestProfile> store)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;

        public Task<IdentityUserPage<TestProfile>> QueryAsync(
            IdentityUserStoreQuery query,
            DateTimeOffset now)
            => store.QueryAsync(query, now, CancellationToken.None);

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }

    public sealed record TestProfile(string DisplayName);
}
