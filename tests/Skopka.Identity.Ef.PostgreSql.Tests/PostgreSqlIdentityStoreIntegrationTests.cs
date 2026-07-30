using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Registration;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Users.Queries;
using Testcontainers.PostgreSql;
using Xunit;

namespace Skopka.Identity.Ef.PostgreSql.Tests;

public sealed class PostgreSqlIdentityStoreIntegrationTests
    : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgreSql =
        new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("skopka_identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

    private ServiceProvider serviceProvider = null!;

    public async Task InitializeAsync()
    {
        await postgreSql.StartAsync();

        var services = new ServiceCollection();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePostgreSql(postgreSql.GetConnectionString());

        serviceProvider = services.BuildServiceProvider(
            new ServiceProviderOptions
            {
                ValidateOnBuild = true,
                ValidateScopes = true
            });

        await using var scope = serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (serviceProvider is not null)
        {
            await serviceProvider.DisposeAsync();
        }

        await postgreSql.DisposeAsync();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task MigrationsAndStoreContractsRunAgainstPostgreSql()
    {
        await AssertAllMigrationsAppliedAsync();

        var now = new DateTimeOffset(
            2026,
            7,
            28,
            12,
            0,
            0,
            TimeSpan.Zero);
        await AssertRateLimitRotationAsync(now);
        var created = await CreateUserAsync(
            "alice",
            "alice@example.com",
            "+15551234567",
            "ALICE",
            "ALICE@EXAMPLE.COM",
            "+15551234567",
            new TestProfile("Alice", ["admin", "support"]),
            now);

        await AssertProfileRoundTripAsync(created);
        await AssertDuplicateEmailIsMappedAsync(now.AddMinutes(1));

        await SoftDeleteAsync(created, now.AddMinutes(2));

        var replacement = await CreateUserAsync(
            "alice",
            "alice@example.com",
            "+15551234567",
            "ALICE",
            "ALICE@EXAMPLE.COM",
            "+15551234567",
            new TestProfile("Replacement", ["user"]),
            now.AddMinutes(3));

        await AssertRestoreCollisionIsMappedAsync(
            created.Id,
            now.AddMinutes(4));
        await AssertDatabaseConcurrencyTokenAsync(
            replacement.Id,
            now.AddMinutes(5));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task AtomicExternalRegistrationAndSessionMetadataRunAgainstPostgreSql()
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var registrationStore = services.GetRequiredService<
            IIdentityRegistrationStore<TestProfile>>();
        var userStore = services.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var sessionStore = services.GetRequiredService<
            IIdentityRefreshSessionStore<TestProfile>>();
        var userQueries = services.GetRequiredService<
            IIdentityUserQueryService<TestProfile>>();
        var now = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            0,
            0,
            TimeSpan.Zero);
        var login = new ExternalLoginKey("GITHUB", "subject-1");
        var userId = Guid.NewGuid();
        var created = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(userId, "external-user"),
            new NormalizedHandles("EXTERNAL-USER", null, null),
            login,
            now,
            CancellationToken.None);
        Assert.True(created.IsSuccess);

        var secondUserId = Guid.NewGuid();
        var second = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(secondUserId, "external-second"),
            new NormalizedHandles("EXTERNAL-SECOND", null, null),
            new ExternalLoginKey("GITHUB", "subject-2"),
            now.AddSeconds(1),
            CancellationToken.None);
        Assert.True(second.IsSuccess);

        var rejectedUserId = Guid.NewGuid();
        var duplicate = await registrationStore.CreateWithExternalLoginAsync(
            NewUser(rejectedUserId, "duplicate"),
            new NormalizedHandles("DUPLICATE", null, null),
            login,
            now.AddMinutes(1),
            CancellationToken.None);
        Assert.False(duplicate.IsSuccess);
        Assert.Contains(
            duplicate.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateExternalLogin);
        Assert.Null(
            await userStore.FindByIdAsync(
                rejectedUserId,
                CancellationToken.None));

        var queried = await userQueries.QueryAsync(
            new IdentityUserQuery(
                Search: "external",
                Status: IdentityUserStatus.Active,
                PageSize: 1),
            CancellationToken.None);
        Assert.True(queried.IsSuccess);
        Assert.Equal(secondUserId, Assert.Single(queried.Value.Items).Id);
        Assert.NotNull(queried.Value.NextCursor);

        var nextPage = await userQueries.QueryAsync(
            new IdentityUserQuery(
                Search: "external",
                Status: IdentityUserStatus.Active,
                PageSize: 1,
                Cursor: queried.Value.NextCursor),
            CancellationToken.None);
        Assert.True(nextPage.IsSuccess);
        Assert.Equal(userId, Assert.Single(nextPage.Value.Items).Id);
        Assert.Null(nextPage.Value.NextCursor);

        var session = new NewRefreshSession(
            Guid.NewGuid(),
            Guid.NewGuid(),
            userId,
            new string('A', SessionLimits.TokenHashLength),
            created.Value.SecurityStamp,
            now.AddDays(1),
            new IdentitySessionMetadata("web", "integration-test"));
        var sessionCreated = await sessionStore.CreateAsync(
            session,
            now,
            CancellationToken.None);
        Assert.True(sessionCreated.IsSuccess);

        var listed = await sessionStore.ListActiveAsync(
            userId,
            now,
            CancellationToken.None);
        var active = Assert.Single(listed);
        Assert.Equal(session.SessionId, active.SessionId);
        Assert.Equal(session.Metadata, active.Metadata);
    }

    private async Task AssertAllMigrationsAppliedAsync()
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();

        var expected = context.Database.GetMigrations().ToArray();
        var applied = (await context.Database.GetAppliedMigrationsAsync())
            .ToArray();

        Assert.NotEmpty(expected);
        Assert.Equal(expected, applied);
        Assert.False(context.Database.HasPendingModelChanges());
    }

    private async Task AssertRateLimitRotationAsync(
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var store = services.GetRequiredService<
            IRateLimitBucketStore<TestProfile>>();
        var context = services.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        var previous = new RateLimitPartition(
            RateLimitLimits.LegacyPartitionVersion,
            new string('A', RateLimitLimits.KeyHashLength));
        var current = new RateLimitPartition(
            "rate-limit-2026-07",
            new string('B', RateLimitLimits.KeyHashLength));

        Assert.True(
            (await store.HitAsync(
                "integration.rotation",
                [previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now,
                CancellationToken.None)).IsAllowed);
        Assert.True(
            (await store.HitAsync(
                "integration.rotation",
                [current, previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now.AddSeconds(1),
                CancellationToken.None)).IsAllowed);
        Assert.False(
            (await store.HitAsync(
                "integration.rotation",
                [previous],
                permitLimit: 2,
                TimeSpan.FromMinutes(1),
                minimumInterval: null,
                now.AddSeconds(2),
                CancellationToken.None)).IsAllowed);

        var buckets = await context.RateLimitBuckets
            .Where(bucket =>
                bucket.Scope == "integration.rotation")
            .OrderBy(bucket => bucket.PartitionVersion)
            .ToListAsync();
        Assert.Equal(2, buckets.Count);
        Assert.All(
            buckets,
            bucket => Assert.Equal(2, bucket.HitCount));
        Assert.Equal(
            [
                RateLimitLimits.LegacyPartitionVersion,
                "rate-limit-2026-07",
            ],
            buckets.Select(bucket => bucket.PartitionVersion));
    }

    private static NewIdentityUser<TestProfile> NewUser(
        Guid id,
        string userName)
        => new(
            userName,
            null,
            null,
            new TestProfile(userName, []),
            UserFlags.None,
            $"STAMP-{Guid.NewGuid():N}",
            id);

    private async Task<IdentityUser<TestProfile>> CreateUserAsync(
        string userName,
        string email,
        string phone,
        string normalizedUserName,
        string normalizedEmail,
        string normalizedPhone,
        TestProfile profile,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.CreateAsync(
            new NewIdentityUser<TestProfile>(
                userName,
                email,
                phone,
                profile,
                UserFlags.None,
                $"STAMP-{Guid.NewGuid():N}"),
            new NormalizedHandles(
                normalizedUserName,
                normalizedEmail,
                normalizedPhone),
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        return result.Value;
    }

    private async Task AssertProfileRoundTripAsync(
        IdentityUser<TestProfile> created)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var found = await store.FindByIdAsync(
            created.Id,
            CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(created.Id, found.Id);
        Assert.Equal(created.Flags, found.Flags);
        Assert.Equal(created.UserName, found.UserName);
        Assert.Equal(created.Email, found.Email);
        Assert.Equal(created.Phone, found.Phone);
        Assert.Equal(created.Profile.DisplayName, found.Profile.DisplayName);
        Assert.Equal(["admin", "support"], found.Profile.Tags);
        Assert.Equal(created.Version, found.Version);
        Assert.Equal(created.SecurityStamp, found.SecurityStamp);
        Assert.Equal(created.CreatedAt, found.CreatedAt);
        Assert.Equal(created.ModifiedAt, found.ModifiedAt);
    }

    private async Task AssertDuplicateEmailIsMappedAsync(
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
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
                null),
            now,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.DuplicateEmail);
    }

    private async Task SoftDeleteAsync(
        IdentityUser<TestProfile> user,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();

        var result = await store.UpdateStateAsync(
            user.Id,
            user.Version,
            now,
            user.BlockedAt,
            user.BlockedUntil,
            "DELETED-STAMP",
            now,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
    }

    private async Task AssertRestoreCollisionIsMappedAsync(
        Guid userId,
        DateTimeOffset now)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<
            IIdentityUserStore<TestProfile>>();
        var deleted = await store.FindByIdAsync(
            userId,
            CancellationToken.None);

        Assert.NotNull(deleted);
        var result = await store.UpdateStateAsync(
            deleted.Id,
            deleted.Version,
            deletedAt: null,
            deleted.BlockedAt,
            deleted.BlockedUntil,
            newSecurityStamp: null,
            now,
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code is IdentityErrorCodes.DuplicateUserName
                or IdentityErrorCodes.DuplicateEmail
                or IdentityErrorCodes.DuplicatePhone);
    }

    private async Task AssertDatabaseConcurrencyTokenAsync(
        Guid userId,
        DateTimeOffset now)
    {
        await using var firstScope = serviceProvider.CreateAsyncScope();
        await using var secondScope = serviceProvider.CreateAsyncScope();
        var firstContext = firstScope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();
        var secondContext = secondScope.ServiceProvider.GetRequiredService<
            PostgreSqlIdentityDbContext<TestProfile>>();

        var firstUser = await firstContext.Users.SingleAsync(
            user => user.Id == userId);
        var secondUser = await secondContext.Users.SingleAsync(
            user => user.Id == userId);

        firstUser.Version++;
        firstUser.ModifiedAt = now;
        secondUser.Version++;
        secondUser.ModifiedAt = now.AddSeconds(1);

        await firstContext.SaveChangesAsync();
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(
            () => secondContext.SaveChangesAsync());
    }

    public sealed record TestProfile(
        string DisplayName,
        IReadOnlyList<string> Tags);
}
