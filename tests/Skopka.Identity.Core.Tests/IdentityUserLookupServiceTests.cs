using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityUserLookupServiceTests
{
    [Fact]
    public async Task FindsActiveUserByNormalizedEmail()
    {
        var user = CreateUser();
        var store = new FakeLookupStore(user);
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            " Alice@Example.com ",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(user, result.Value);
        Assert.Equal(
            "ALICE@EXAMPLE.COM",
            store.NormalizedEmail);
    }

    [Fact]
    public async Task UnknownEmailReturnsNotFound()
    {
        var service = new IdentityUserLookupService<TestProfile>(
            new FakeLookupStore(null),
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            "unknown@example.com",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task EmptyEmailReturnsValidationWithoutStoreCall()
    {
        var store = new FakeLookupStore(CreateUser());
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            " ",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.Validation);
        Assert.Null(store.NormalizedEmail);
    }

    [Fact]
    public async Task FindsActiveUserByNormalizedPhone()
    {
        var user = CreateUser();
        var store = new FakeLookupStore(user);
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "+1 (234) 567-8901",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(user, result.Value);
        Assert.Equal("12345678901", store.NormalizedPhone);
    }

    [Fact]
    public async Task UnknownPhoneReturnsNotFound()
    {
        var service = new IdentityUserLookupService<TestProfile>(
            new FakeLookupStore(null),
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "+1 (234) 567-8901",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task InvalidPhoneReturnsValidationWithoutStoreCall()
    {
        var store = new FakeLookupStore(CreateUser());
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "call12345678",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.Validation);
        Assert.Null(store.NormalizedPhone);
    }

    private static IdentityUser<TestProfile> CreateUser()
        => new(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            false,
            null,
            false,
            new TestProfile("Alice"),
            1,
            "SECURITY-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);

    private sealed class FakeLookupStore(
        IdentityUser<TestProfile>? user)
        : IIdentityUserLookupStore<TestProfile>
    {
        public string? NormalizedEmail { get; private set; }
        public string? NormalizedPhone { get; private set; }

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedUserNameAsync(
                string normalizedUserName,
                CancellationToken ct)
            => Task.FromResult<IdentityUser<TestProfile>?>(null);

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedEmailAsync(
                string normalizedEmail,
                CancellationToken ct)
        {
            NormalizedEmail = normalizedEmail;
            return Task.FromResult(user);
        }

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedPhoneAsync(
                string normalizedPhone,
                CancellationToken ct)
        {
            NormalizedPhone = normalizedPhone;
            return Task.FromResult(user);
        }
    }

    private sealed record TestProfile(string DisplayName);
}
