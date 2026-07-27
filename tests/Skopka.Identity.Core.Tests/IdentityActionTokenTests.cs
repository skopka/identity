using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Tokens;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityActionTokenTests
{
    [Fact]
    public async Task IssuerBindsEmailTokenToUserHandleAndSecurityStamp()
    {
        var userStore = new FakeIdentityUserStore(CreateUser());
        var provider = new FakeActionTokenProvider();
        var issuer = new IdentityActionTokenIssuer<TestProfile>(
            userStore,
            new DefaultIdentityNormalizer(),
            new DefaultUserOperationPolicy(),
            provider,
            new IdentityActionTokenOptions
            {
                EmailConfirmationLifetime = TimeSpan.FromMinutes(30),
            },
            new NoopIdentityMetrics());

        var before = DateTimeOffset.UtcNow;
        var result = await issuer.IssueEmailConfirmationAsync(
            userStore.User.Id,
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("token-1", result.Value.Token);
        Assert.NotNull(provider.LastGeneratedPayload);
        Assert.Equal(
            IdentityActionTokenPurpose.EmailConfirmation,
            provider.LastGeneratedPayload.Purpose);
        Assert.Equal(userStore.User.Id, provider.LastGeneratedPayload.UserId);
        Assert.Equal(userStore.User.SecurityStamp, provider.LastGeneratedPayload.SecurityStamp);
        Assert.Equal("ALICE@EXAMPLE.COM", provider.LastGeneratedPayload.Target);
        Assert.InRange(
            provider.LastGeneratedPayload.ExpiresAt,
            before.AddMinutes(30),
            DateTimeOffset.UtcNow.AddMinutes(30));
    }

    [Fact]
    public async Task ConfirmEmailAcceptsMatchingToken()
    {
        var fixture = new UserServiceFixture();
        var token = fixture.Provider.Add(
            CreatePayload(
                fixture.Store.User,
                IdentityActionTokenPurpose.EmailConfirmation,
                "ALICE@EXAMPLE.COM"));

        var result = await fixture.Service.ConfirmEmailAsync(
            new ConfirmEmailCommand(
                fixture.Store.User.Id,
                "alice@example.com",
                token),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.EmailConfirmed);
        Assert.Equal(1, fixture.Store.UpdateHandlesCalls);
    }

    [Fact]
    public async Task ConfirmPhoneAcceptsMatchingToken()
    {
        var fixture = new UserServiceFixture();
        var token = fixture.Provider.Add(
            CreatePayload(
                fixture.Store.User,
                IdentityActionTokenPurpose.PhoneConfirmation,
                "15551234567"));

        var result = await fixture.Service.ConfirmPhoneAsync(
            new ConfirmPhoneCommand(
                fixture.Store.User.Id,
                "+1 (555) 123-4567",
                token),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.PhoneConfirmed);
        Assert.Equal(1, fixture.Store.UpdateHandlesCalls);
    }

    [Theory]
    [InlineData("wrong-target")]
    [InlineData("wrong-stamp")]
    [InlineData("expired")]
    [InlineData("wrong-purpose")]
    public async Task ConfirmEmailRejectsTokenWithInvalidBinding(string invalidPart)
    {
        var fixture = new UserServiceFixture();
        var user = fixture.Store.User;
        var purpose = invalidPart == "wrong-purpose"
            ? IdentityActionTokenPurpose.PasswordReset
            : IdentityActionTokenPurpose.EmailConfirmation;
        var target = invalidPart == "wrong-target"
            ? "OTHER@EXAMPLE.COM"
            : "ALICE@EXAMPLE.COM";
        var stamp = invalidPart == "wrong-stamp"
            ? "OTHER-STAMP"
            : user.SecurityStamp;
        var expiresAt = invalidPart == "expired"
            ? DateTimeOffset.UtcNow.AddMinutes(-1)
            : DateTimeOffset.UtcNow.AddMinutes(10);
        var token = fixture.Provider.Add(
            new IdentityActionTokenPayload(
                1,
                purpose,
                user.Id,
                stamp,
                target,
                DateTimeOffset.UtcNow.AddMinutes(-5),
                expiresAt));

        var result = await fixture.Service.ConfirmEmailAsync(
            new ConfirmEmailCommand(user.Id, user.Email!, token),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidActionToken);
        Assert.Equal(0, fixture.Store.UpdateHandlesCalls);
    }

    [Fact]
    public async Task ResetPasswordRotatesStampAndInvalidatesUsedToken()
    {
        var userStore = new FakeIdentityUserStore(CreateUser());
        var credentialStore = new FakePasswordCredentialStore(
            userStore,
            "hash:old password");
        var provider = new FakeActionTokenProvider();
        var token = provider.Add(
            CreatePayload(
                userStore.User,
                IdentityActionTokenPurpose.PasswordReset,
                target: null));
        var service = new PasswordCredentialService<TestProfile>(
            userStore,
            credentialStore,
            new FakePasswordHasher(),
            new FakeSecurityStampGenerator(),
            new DefaultUserOperationPolicy(),
            new NoopIdentityMetrics(),
            [provider]);

        var command = new ResetPasswordCommand(
            userStore.User.Id,
            token,
            "new password");
        var first = await service.ResetPasswordAsync(command, CancellationToken.None);
        var second = await service.ResetPasswordAsync(command, CancellationToken.None);

        Assert.True(first.IsSuccess);
        AssertError(second, IdentityErrorCodes.InvalidActionToken);
        Assert.Equal("hash:new password", credentialStore.PasswordVerifier);
        Assert.Equal("NEW-STAMP", userStore.User.SecurityStamp);
        Assert.Equal(1, credentialStore.ReplaceCalls);
    }

    [Fact]
    public async Task ResetPasswordCanCreateMissingPasswordCredential()
    {
        var userStore = new FakeIdentityUserStore(CreateUser());
        var credentialStore = new FakePasswordCredentialStore(userStore, null);
        var provider = new FakeActionTokenProvider();
        var token = provider.Add(
            CreatePayload(
                userStore.User,
                IdentityActionTokenPurpose.PasswordReset,
                target: null));
        var service = new PasswordCredentialService<TestProfile>(
            userStore,
            credentialStore,
            new FakePasswordHasher(),
            new FakeSecurityStampGenerator(),
            new DefaultUserOperationPolicy(),
            new NoopIdentityMetrics(),
            [provider]);

        var result = await service.ResetPasswordAsync(
            new ResetPasswordCommand(userStore.User.Id, token, "new password"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Null(credentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("hash:new password", credentialStore.PasswordVerifier);
    }

    private static IdentityActionTokenPayload CreatePayload(
        IdentityUser<TestProfile> user,
        IdentityActionTokenPurpose purpose,
        string? target)
        => new(
            1,
            purpose,
            user.Id,
            user.SecurityStamp,
            target,
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(10));

    private static IdentityUser<TestProfile> CreateUser()
        => new(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            false,
            "+15551234567",
            false,
            new TestProfile("Alice"),
            3,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    private static void AssertError(OperationResult result, string errorCode)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == errorCode);
    }

    private sealed class UserServiceFixture
    {
        public UserServiceFixture()
        {
            Store = new FakeIdentityUserStore(CreateUser());
            Provider = new FakeActionTokenProvider();
            Service = new IdentityUserService<TestProfile>(
                Store,
                new DefaultIdentityNormalizer(),
                new DefaultUserOperationPolicy(),
                new FakeSecurityStampGenerator(),
                new NoopIdentityMetrics(),
                [Provider]);
        }

        public FakeIdentityUserStore Store { get; }
        public FakeActionTokenProvider Provider { get; }
        public IdentityUserService<TestProfile> Service { get; }
    }

    private sealed class FakeActionTokenProvider : IIdentityActionTokenProvider
    {
        private readonly Dictionary<string, IdentityActionTokenPayload> tokens = [];

        public IdentityActionTokenPayload? LastGeneratedPayload { get; private set; }

        public string Generate(IdentityActionTokenPayload payload)
        {
            LastGeneratedPayload = payload;
            return Add(payload);
        }

        public bool TryRead(
            string token,
            IdentityActionTokenPurpose expectedPurpose,
            out IdentityActionTokenPayload? payload)
        {
            if (tokens.TryGetValue(token, out payload)
                && payload.Purpose == expectedPurpose)
            {
                return true;
            }

            payload = null;
            return false;
        }

        public string Add(IdentityActionTokenPayload payload)
        {
            var token = $"token-{tokens.Count + 1}";
            tokens.Add(token, payload);
            return token;
        }
    }

    private sealed class FakePasswordCredentialStore(
        FakeIdentityUserStore userStore,
        string? passwordVerifier)
        : IPasswordCredentialStore<TestProfile>
    {
        public string? PasswordVerifier { get; private set; } = passwordVerifier;
        public string? LastExpectedPasswordVerifier { get; private set; }
        public int ReplaceCalls { get; private set; }

        public Task<string?> FindPasswordVerifierAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult(PasswordVerifier);

        public Task<OperationResult> ReplacePasswordVerifierAsync(
            Guid userId,
            long expectedVersion,
            string? expectedPasswordVerifier,
            string? newPasswordVerifier,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
        {
            ReplaceCalls++;
            LastExpectedPasswordVerifier = expectedPasswordVerifier;
            PasswordVerifier = newPasswordVerifier;
            userStore.User = userStore.User with
            {
                Version = userStore.User.Version + 1,
                SecurityStamp = newSecurityStamp ?? userStore.User.SecurityStamp,
                ModifiedAt = now,
            };

            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakePasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password) => $"hash:{password}";

        public PasswordVerificationResult VerifyHashedPassword(
            string passwordVerifier,
            string providedPassword)
            => passwordVerifier == $"hash:{providedPassword}"
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
    }

    private sealed class FakeSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "NEW-STAMP";
    }

    private sealed class FakeIdentityUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; set; } = user;
        public int UpdateHandlesCalls { get; private set; }

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> newUser,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateHandlesAsync(
            Guid userId,
            long expectedVersion,
            UpdatedHandles updated,
            DateTimeOffset now,
            CancellationToken ct)
        {
            UpdateHandlesCalls++;
            User = User with
            {
                UserName = updated.UserName,
                Email = updated.Email,
                EmailConfirmed = updated.EmailConfirmed,
                Phone = updated.Phone,
                PhoneConfirmed = updated.PhoneConfirmed,
                Version = User.Version + 1,
                ModifiedAt = now,
            };

            return Task.FromResult(OperationResultFactory.Success(User));
        }

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(
            Guid userId,
            long expectedVersion,
            TestProfile profile,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateSecurityStampAsync(
            Guid userId,
            long expectedVersion,
            string securityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    public sealed record TestProfile(string DisplayName);
}
