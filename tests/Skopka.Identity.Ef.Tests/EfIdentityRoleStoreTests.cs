using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Errors;
using Skopka.Identity.Roles;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityRoleStoreTests
{
    [Fact]
    public async Task CreateUpdateAndFindPersistRole()
    {
        await using var database = await TestDatabase.CreateAsync();
        var createdAt = database.Now;

        var created = await database.RoleStore.CreateAsync(
            new NewIdentityRole(
                "Operator",
                "OPERATOR",
                "Operations",
                null),
            createdAt,
            CancellationToken.None);

        Assert.True(created.IsSuccess);
        Assert.Equal(1, created.Value.Version);
        Assert.Equal(
            created.Value,
            await database.RoleStore.FindByNormalizedNameAsync(
                "OPERATOR",
                CancellationToken.None));

        var modifiedAt = createdAt.AddMinutes(1);
        var updated = await database.RoleStore.UpdateAsync(
            created.Value.Id,
            created.Value.Version,
            new UpdatedIdentityRole(
                "Administrator",
                "ADMINISTRATOR",
                null,
                null),
            modifiedAt,
            CancellationToken.None);

        Assert.True(updated.IsSuccess);
        Assert.Equal(2, updated.Value.Version);
        Assert.Equal("Administrator", updated.Value.Name);
        Assert.Equal(modifiedAt, updated.Value.ModifiedAt);
    }

    [Fact]
    public async Task StaleRoleVersionReturnsConcurrencyConflict()
    {
        await using var database = await TestDatabase.CreateAsync();
        var role = await database.CreateRoleAsync("Operator");

        var result = await database.RoleStore.UpdateAsync(
            role.Id,
            role.Version + 1,
            new UpdatedIdentityRole(
                role.Name,
                role.Name.ToUpperInvariant(),
                role.Description,
                role.ParentId),
            database.Now.AddMinutes(1),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
    }

    [Fact]
    public async Task AddListCheckAndRemoveMembership()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync();
        var role = await database.CreateRoleAsync("Operator");

        var added = await database.UserRoleStore.AddAsync(
            user.Id,
            role.Id,
            database.Now,
            CancellationToken.None);

        Assert.True(added.IsSuccess);
        Assert.True(await database.UserRoleStore.IsInRoleAsync(
            user.Id,
            role.Id,
            CancellationToken.None));
        Assert.Equal(
            role,
            Assert.Single(await database.UserRoleStore.GetRolesAsync(
                user.Id,
                CancellationToken.None)));

        var removed = await database.UserRoleStore.RemoveAsync(
            user.Id,
            role.Id,
            CancellationToken.None);
        var removedAgain = await database.UserRoleStore.RemoveAsync(
            user.Id,
            role.Id,
            CancellationToken.None);

        Assert.True(removed.IsSuccess);
        Assert.True(removedAgain.IsSuccess);
        Assert.False(await database.UserRoleStore.IsInRoleAsync(
            user.Id,
            role.Id,
            CancellationToken.None));
    }

    [Fact]
    public async Task DuplicateMembershipReturnsStableConflict()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync();
        var role = await database.CreateRoleAsync("Operator");
        Assert.True((await database.UserRoleStore.AddAsync(
            user.Id,
            role.Id,
            database.Now,
            CancellationToken.None)).IsSuccess);

        var duplicate = await database.UserRoleStore.AddAsync(
            user.Id,
            role.Id,
            database.Now,
            CancellationToken.None);

        AssertError(duplicate, IdentityErrorCodes.RoleAlreadyAssigned);
    }

    [Fact]
    public async Task DeleteRoleCascadesMembership()
    {
        await using var database = await TestDatabase.CreateAsync();
        var user = await database.CreateUserAsync();
        var role = await database.CreateRoleAsync("Operator");
        Assert.True((await database.UserRoleStore.AddAsync(
            user.Id,
            role.Id,
            database.Now,
            CancellationToken.None)).IsSuccess);

        var deleted = await database.RoleStore.DeleteAsync(
            role.Id,
            role.Version,
            CancellationToken.None);

        Assert.True(deleted.IsSuccess);
        Assert.False(await database.UserRoleStore.IsInRoleAsync(
            user.Id,
            role.Id,
            CancellationToken.None));
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
        EfIdentityUserStore<TestProfile> userStore,
        EfIdentityRoleStore<TestProfile> roleStore,
        EfIdentityUserRoleStore<TestProfile> userRoleStore,
        DateTimeOffset now)
        : IAsyncDisposable
    {
        public IdentityDbContext<TestProfile> Context { get; } = context;
        public EfIdentityUserStore<TestProfile> UserStore { get; } = userStore;
        public EfIdentityRoleStore<TestProfile> RoleStore { get; } = roleStore;
        public EfIdentityUserRoleStore<TestProfile> UserRoleStore { get; } =
            userRoleStore;
        public DateTimeOffset Now { get; } = now;

        public static async Task<TestDatabase> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<
                    IdentityDbContext<TestProfile>>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
                .Options;
            var context = new IdentityDbContext<TestProfile>(options);
            await context.Database.EnsureCreatedAsync();

            return new TestDatabase(
                context,
                new EfIdentityUserStore<TestProfile>(context),
                new EfIdentityRoleStore<TestProfile>(context),
                new EfIdentityUserRoleStore<TestProfile>(context),
                new DateTimeOffset(
                    2026,
                    7,
                    28,
                    12,
                    0,
                    0,
                    TimeSpan.Zero));
        }

        public async Task<IdentityUser<TestProfile>> CreateUserAsync()
        {
            var result = await UserStore.CreateAsync(
                new NewIdentityUser<TestProfile>(
                    "alice",
                    "alice@example.com",
                    null,
                    new TestProfile("Alice"),
                    UserFlags.None,
                    "SECURITY-STAMP"),
                new NormalizedHandles(
                    "ALICE",
                    "ALICE@EXAMPLE.COM",
                    null),
                Now,
                CancellationToken.None);

            Assert.True(result.IsSuccess);
            return result.Value;
        }

        public async Task<IdentityRole> CreateRoleAsync(string name)
        {
            var result = await RoleStore.CreateAsync(
                new NewIdentityRole(
                    name,
                    name.ToUpperInvariant(),
                    null,
                    null),
                Now,
                CancellationToken.None);

            Assert.True(result.IsSuccess);
            return result.Value;
        }

        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }
}
