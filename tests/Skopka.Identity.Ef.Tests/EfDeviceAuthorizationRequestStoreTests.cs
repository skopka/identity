using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;
using Xunit;

namespace Skopka.Identity.Ef.Tests;

public sealed class EfDeviceAuthorizationRequestStoreTests
{
    [Fact]
    public async Task RequestTransitionsThroughApprovalAndConsumptionOnce()
    {
        await using var context = CreateContext();
        await context.Database.EnsureCreatedAsync();
        var store = new EfDeviceAuthorizationRequestStore<TestProfile>(context);
        var created = NewRequest();
        var now = DateTimeOffset.UtcNow;
        Assert.True((await store.CreateAsync(
            created,
            now,
            CancellationToken.None)).IsSuccess);
        var pending = await store.FindByDeviceCodeAsync(
            created.DeviceCode,
            CancellationToken.None);

        var approved = await store.ApproveAsync(
            pending!.Id,
            pending.Version,
            Guid.NewGuid(),
            "security-stamp",
            now.AddSeconds(1),
            CancellationToken.None);
        var consumptionId = Guid.NewGuid();
        var claimed = await store.BeginConsumeAsync(
            approved.Value.Id,
            approved.Value.Version,
            consumptionId,
            now.AddSeconds(2),
            CancellationToken.None);
        var sessionId = Guid.NewGuid();
        var consumed = await store.CompleteConsumeAsync(
            claimed.Value.Id,
            consumptionId,
            sessionId,
            now.AddSeconds(3),
            CancellationToken.None);
        var replay = await store.BeginConsumeAsync(
            claimed.Value.Id,
            claimed.Value.Version,
            Guid.NewGuid(),
            now.AddSeconds(4),
            CancellationToken.None);

        Assert.True(consumed.IsSuccess);
        Assert.False(replay.IsSuccess);
        Assert.Contains(
            replay.Errors,
            error => error.Code
                == IdentityErrorCodes.DeviceAuthorizationStateInvalid);
        var stored = await store.FindByDeviceCodeAsync(
            created.DeviceCode,
            CancellationToken.None);
        Assert.Equal(DeviceAuthorizationState.Consumed, stored!.State);
        Assert.Equal(sessionId, stored.SessionId);
    }

    [Fact]
    public async Task ReleaseReturnsFailedConsumptionToApproved()
    {
        await using var context = CreateContext();
        await context.Database.EnsureCreatedAsync();
        var store = new EfDeviceAuthorizationRequestStore<TestProfile>(context);
        var created = NewRequest();
        var now = DateTimeOffset.UtcNow;
        await store.CreateAsync(created, now, CancellationToken.None);
        var pending = await store.FindByDeviceCodeAsync(
            created.DeviceCode,
            CancellationToken.None);
        var approved = await store.ApproveAsync(
            pending!.Id,
            pending.Version,
            Guid.NewGuid(),
            "security-stamp",
            now.AddSeconds(1),
            CancellationToken.None);
        var consumptionId = Guid.NewGuid();
        var claimed = await store.BeginConsumeAsync(
            approved.Value.Id,
            approved.Value.Version,
            consumptionId,
            now.AddSeconds(2),
            CancellationToken.None);

        var released = await store.ReleaseConsumeAsync(
            claimed.Value.Id,
            consumptionId,
            now.AddSeconds(3),
            CancellationToken.None);

        Assert.True(released.IsSuccess);
        Assert.Equal(
            DeviceAuthorizationState.Approved,
            released.Value.State);
        Assert.Null(released.Value.ConsumptionId);
    }

    [Fact]
    public async Task ConcurrentConsumptionClaimHasOneWinner()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString("N");
        await using var setup = CreateContext(name, root);
        await setup.Database.EnsureCreatedAsync();
        var setupStore = new EfDeviceAuthorizationRequestStore<TestProfile>(
            setup);
        var created = NewRequest();
        var now = DateTimeOffset.UtcNow;
        await setupStore.CreateAsync(created, now, CancellationToken.None);
        var pending = await setupStore.FindByDeviceCodeAsync(
            created.DeviceCode,
            CancellationToken.None);
        var approved = await setupStore.ApproveAsync(
            pending!.Id,
            pending.Version,
            Guid.NewGuid(),
            "security-stamp",
            now.AddSeconds(1),
            CancellationToken.None);

        await using var firstContext = CreateContext(name, root);
        await using var secondContext = CreateContext(name, root);
        var first = new EfDeviceAuthorizationRequestStore<TestProfile>(
            firstContext);
        var second = new EfDeviceAuthorizationRequestStore<TestProfile>(
            secondContext);
        var results = await Task.WhenAll(
            first.BeginConsumeAsync(
                approved.Value.Id,
                approved.Value.Version,
                Guid.NewGuid(),
                now.AddSeconds(2),
                CancellationToken.None),
            second.BeginConsumeAsync(
                approved.Value.Id,
                approved.Value.Version,
                Guid.NewGuid(),
                now.AddSeconds(2),
                CancellationToken.None));

        Assert.Single(results, result => result.IsSuccess);
    }

    [Fact]
    public void ModelConfiguresDeviceCodeUniquenessAndVersionConcurrency()
    {
        using var context = CreateContext();
        var entity = context.Model.FindEntityType(
            "Skopka.Identity.Ef.Entities.DeviceAuthorizationRequestEntity");

        Assert.NotNull(entity);
        Assert.True(entity.FindProperty("Version")!.IsConcurrencyToken);
        Assert.Contains(
            entity.GetIndexes(),
            index => index.IsUnique
                && index.Properties.Single().Name == "DeviceCode");
    }

    [Fact]
    public async Task PruneRemovesOnlyRequestsPastRetentionCutoff()
    {
        await using var context = CreateContext();
        await context.Database.EnsureCreatedAsync();
        var store = new EfDeviceAuthorizationRequestStore<TestProfile>(context);
        var now = DateTimeOffset.UtcNow;
        var old = NewRequest() with
        {
            ExpiresAt = now.AddDays(-2),
        };
        var recent = NewRequest() with
        {
            ExpiresAt = now,
        };
        await store.CreateAsync(old, now.AddDays(-3), CancellationToken.None);
        await store.CreateAsync(recent, now, CancellationToken.None);

        var removed = await store.PruneAsync(
            now.AddDays(-1),
            10,
            CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Null(await store.FindByDeviceCodeAsync(
            old.DeviceCode,
            CancellationToken.None));
        Assert.NotNull(await store.FindByDeviceCodeAsync(
            recent.DeviceCode,
            CancellationToken.None));
    }

    private static NewDeviceAuthorizationRequest NewRequest()
        => new(
            Guid.NewGuid(),
            Guid.NewGuid().ToString("N"),
            new string('A', 64),
            "ABCD-EFGH",
            new DeviceAuthorizationMetadata(
                "127.0.0.1",
                "Browser",
                "Browser on OS",
                "client",
                "/connect/authorize?client_id=client",
                new IdentitySessionMetadata("Hello", "Browser on OS")),
            DateTimeOffset.UtcNow.AddMinutes(2));

    private static IdentityDbContext<TestProfile> CreateContext(
        string? name = null,
        InMemoryDatabaseRoot? root = null)
    {
        var builder = new DbContextOptionsBuilder<
            IdentityDbContext<TestProfile>>();
        builder.UseInMemoryDatabase(
            name ?? Guid.NewGuid().ToString("N"),
            root ?? new InMemoryDatabaseRoot());
        return new IdentityDbContext<TestProfile>(builder.Options);
    }

    private sealed record TestProfile(string DisplayName);
}
