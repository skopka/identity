using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
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
