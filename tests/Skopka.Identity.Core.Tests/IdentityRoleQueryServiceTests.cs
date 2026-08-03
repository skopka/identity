using Skopka.Identity.Metrics;
using Skopka.Identity.Roles;
using Skopka.Identity.Roles.Queries;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityRoleQueryServiceTests
{
    [Fact]
    public async Task QueryNormalizesSearchBeforeCallingStore()
    {
        var store = new FakeStore();
        var service = new IdentityRoleQueryService<TestProfile>(
            store,
            new DefaultIdentityRoleNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityRoleQuery("  Administrators  "),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("ADMINISTRATORS", store.Query!.NormalizedName);
    }

    [Fact]
    public async Task QueryRejectsUnboundedPageSize()
    {
        var store = new FakeStore();
        var service = new IdentityRoleQueryService<TestProfile>(
            store,
            new DefaultIdentityRoleNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityRoleQuery(
                PageSize: IdentityRoleQueryLimits.MaximumPageSize + 1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Null(store.Query);
    }

    [Fact]
    public async Task QueryRejectsEmptyCursorId()
    {
        var store = new FakeStore();
        var service = new IdentityRoleQueryService<TestProfile>(
            store,
            new DefaultIdentityRoleNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.QueryAsync(
            new IdentityRoleQuery(
                Cursor: new IdentityRoleCursor(
                    DateTimeOffset.UtcNow,
                    Guid.Empty)),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Null(store.Query);
    }

    private sealed class FakeStore : IIdentityRoleQueryStore<TestProfile>
    {
        public IdentityRoleStoreQuery? Query { get; private set; }

        public Task<IdentityRolePage> QueryAsync(
            IdentityRoleStoreQuery query,
            CancellationToken ct)
        {
            Query = query;
            return Task.FromResult(new IdentityRolePage([], null));
        }
    }

    public sealed record TestProfile(string DisplayName);
}
