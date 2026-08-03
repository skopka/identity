using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Roles.Queries;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfIdentityRoleQueryStoreTests
{
    [Fact]
    public async Task QueryAppliesNormalizedNameSearch()
    {
        await using var database = CreateDatabase();
        var now = DateTimeOffset.UtcNow;
        AddRole(database.Context, "Administrators", now);
        AddRole(database.Context, "Auditors", now.AddMinutes(-1));
        await database.Context.SaveChangesAsync();

        var page = await database.Store.QueryAsync(
            new IdentityRoleStoreQuery("ADMIN", 10, null),
            CancellationToken.None);

        Assert.Equal(
            "Administrators",
            Assert.Single(page.Items).Name);
        Assert.Null(page.NextCursor);
    }

    [Fact]
    public async Task QueryCursorDoesNotSkipRolesWithSameCreatedAt()
    {
        await using var database = CreateDatabase();
        var createdAt = DateTimeOffset.UtcNow;
        AddRole(
            database.Context,
            "First",
            createdAt,
            Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        AddRole(
            database.Context,
            "Second",
            createdAt,
            Guid.Parse("88888888-8888-8888-8888-888888888888"));
        AddRole(
            database.Context,
            "Third",
            createdAt,
            Guid.Parse("11111111-1111-1111-1111-111111111111"));
        await database.Context.SaveChangesAsync();

        var firstPage = await database.Store.QueryAsync(
            new IdentityRoleStoreQuery(null, 2, null),
            CancellationToken.None);
        var secondPage = await database.Store.QueryAsync(
            new IdentityRoleStoreQuery(
                null,
                2,
                firstPage.NextCursor),
            CancellationToken.None);

        Assert.Equal(2, firstPage.Items.Count);
        Assert.NotNull(firstPage.NextCursor);
        Assert.Single(secondPage.Items);
        Assert.Null(secondPage.NextCursor);
        Assert.Equal(
            3,
            firstPage.Items.Concat(secondPage.Items)
                .Select(role => role.Id)
                .Distinct()
                .Count());
    }

    private static TestDatabase CreateDatabase()
    {
        var options = new DbContextOptionsBuilder<
                IdentityDbContext<TestProfile>>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;
        var context = new IdentityDbContext<TestProfile>(options);
        return new TestDatabase(
            context,
            new EfIdentityRoleQueryStore<TestProfile>(context));
    }

    private static void AddRole(
        IdentityDbContext<TestProfile> context,
        string name,
        DateTimeOffset createdAt,
        Guid? id = null)
    {
        context.Roles.Add(new RoleEntity
        {
            Id = id ?? Guid.NewGuid(),
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            Version = 1,
            CreatedAt = createdAt,
            ModifiedAt = createdAt,
        });
    }

    private sealed record TestDatabase(
        IdentityDbContext<TestProfile> Context,
        EfIdentityRoleQueryStore<TestProfile> Store)
        : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => Context.DisposeAsync();
    }

    public sealed record TestProfile(string DisplayName);
}
