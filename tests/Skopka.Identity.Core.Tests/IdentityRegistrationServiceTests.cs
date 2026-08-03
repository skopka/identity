using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.Registration;
using Skopka.Identity.Security;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityRegistrationServiceTests
{
    [Fact]
    public async Task PasswordRegistrationValidatesHashesAndPersistsOnce()
    {
        var validator = new RecordingPasswordValidator();
        var fixture = new Fixture(
            passwordHasher: new FakePasswordHasher(),
            validators: [validator]);

        var result = await fixture.Service.RegisterPasswordAsync(
            new RegisterPasswordUserCommand<TestProfile>(
                CreateCommand(),
                "correct horse battery staple"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("HASH:correct horse battery staple", fixture.Store.PasswordVerifier);
        Assert.NotNull(fixture.Store.User?.Id);
        Assert.Equal("ALICE", fixture.Store.Handles?.UserName);
        Assert.Equal("ALICE@EXAMPLE.COM", fixture.Store.Handles?.Email);
        Assert.Equal(
            ["ALICE", "ALICE@EXAMPLE.COM"],
            fixture.Store.Handles?.LoginIdentifierKeys);
        Assert.Equal(PasswordMutation.Register, validator.Mutation);
        Assert.Equal(0, validator.UserVersion);
    }

    [Fact]
    public async Task PasswordRegistrationFailsWhenHasherIsNotConfigured()
    {
        var fixture = new Fixture(passwordHasher: null);

        var result = await fixture.Service.RegisterPasswordAsync(
            new RegisterPasswordUserCommand<TestProfile>(
                CreateCommand(),
                "correct horse battery staple"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.PasswordHasherUnavailable);
        Assert.Null(fixture.Store.User);
    }

    [Fact]
    public async Task PasswordRegistrationDoesNotHashRejectedPassword()
    {
        var hasher = new FakePasswordHasher();
        var fixture = new Fixture(
            passwordHasher: hasher,
            validators: [new RejectingPasswordValidator()]);

        var result = await fixture.Service.RegisterPasswordAsync(
            new RegisterPasswordUserCommand<TestProfile>(
                CreateCommand(),
                "correct horse battery staple"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.PasswordRejected);
        Assert.Equal(0, hasher.HashCount);
        Assert.Null(fixture.Store.User);
    }

    [Fact]
    public async Task ExternalRegistrationNormalizesProvider()
    {
        var fixture = new Fixture(passwordHasher: null);

        var result = await fixture.Service.RegisterExternalAsync(
            new RegisterExternalUserCommand<TestProfile>(
                CreateCommand(),
                new ExternalLoginKey("  github ", "Case-Sensitive")),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            new ExternalLoginKey("GITHUB", "Case-Sensitive"),
            fixture.Store.ExternalLogin);
        Assert.NotNull(fixture.Store.User?.Id);
    }

    [Fact]
    public async Task RegistrationRejectsProtectedUser()
    {
        var fixture = new Fixture(passwordHasher: null);
        var command = CreateCommand() with
        {
            Flags = UserFlags.Protected,
        };

        var result = await fixture.Service.RegisterExternalAsync(
            new RegisterExternalUserCommand<TestProfile>(
                command,
                new ExternalLoginKey("github", "subject")),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Forbidden);
        Assert.Null(fixture.Store.User);
    }

    [Fact]
    public async Task RegistrationBuildsUnionOfAutomaticHandleAliases()
    {
        var fixture = new Fixture(passwordHasher: null);
        var command = new CreateUserCommand<TestProfile>(
            "+1 (234) 567-8901",
            null,
            "+1 234 567 8901",
            new TestProfile("Alice"));

        var result = await fixture.Service.RegisterExternalAsync(
            new RegisterExternalUserCommand<TestProfile>(
                command,
                new ExternalLoginKey("github", "subject")),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            ["+1 (234) 567-8901", "12345678901", "+1 234 567 8901"],
            fixture.Store.Handles?.LoginIdentifierKeys);
    }

    [Fact]
    public async Task RegistrationRejectsOversizedHandleBeforeStore()
    {
        var fixture = new Fixture(passwordHasher: null);
        var command = CreateCommand() with
        {
            UserName = new string(
                'x',
                IdentityLoginLimits.MaximumLoginLength + 1),
        };

        var result = await fixture.Service.RegisterExternalAsync(
            new RegisterExternalUserCommand<TestProfile>(
                command,
                new ExternalLoginKey("github", "subject")),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Null(fixture.Store.User);
    }

    [Fact]
    public async Task RegistrationRejectsNonPhoneShapedPhoneBeforeStore()
    {
        var fixture = new Fixture(passwordHasher: null);
        var command = CreateCommand() with
        {
            Phone = "call12345678",
        };

        var result = await fixture.Service.RegisterExternalAsync(
            new RegisterExternalUserCommand<TestProfile>(
                command,
                new ExternalLoginKey("github", "subject")),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Null(fixture.Store.User);
    }

    private static CreateUserCommand<TestProfile> CreateCommand()
        => new(
            "alice",
            "alice@example.com",
            null,
            new TestProfile("Alice"));

    private static void AssertError<T>(
        OperationResult<T> result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class Fixture
    {
        public Fixture(
            IPasswordHasher? passwordHasher,
            IReadOnlyList<IPasswordValidator<TestProfile>>? validators = null)
        {
            Store = new FakeRegistrationStore();
            Service = new IdentityRegistrationService<TestProfile>(
                Store,
                new DefaultIdentityNormalizer(),
                new DefaultUserOperationPolicy(),
                new FakeSecurityStampGenerator(),
                new NoopIdentityMetrics(),
                new PasswordPolicyOptions(),
                passwordHasher is null ? [] : [passwordHasher],
                validators ?? []);
        }

        public FakeRegistrationStore Store { get; }
        public IdentityRegistrationService<TestProfile> Service { get; }
    }

    private sealed class FakeRegistrationStore
        : IIdentityRegistrationStore<TestProfile>
    {
        public NewIdentityUser<TestProfile>? User { get; private set; }
        public NormalizedHandles? Handles { get; private set; }
        public string? PasswordVerifier { get; private set; }
        public ExternalLoginKey? ExternalLogin { get; private set; }

        public Task<OperationResult<IdentityUser<TestProfile>>>
            CreateWithPasswordAsync(
                NewIdentityUser<TestProfile> user,
                NormalizedHandles handles,
                string passwordVerifier,
                DateTimeOffset now,
                CancellationToken ct)
        {
            User = user;
            Handles = handles;
            PasswordVerifier = passwordVerifier;
            return Task.FromResult(
                OperationResultFactory.Success(ToModel(user, now)));
        }

        public Task<OperationResult<IdentityUser<TestProfile>>>
            CreateWithExternalLoginAsync(
                NewIdentityUser<TestProfile> user,
                NormalizedHandles handles,
                ExternalLoginKey login,
                DateTimeOffset now,
                CancellationToken ct)
        {
            User = user;
            Handles = handles;
            ExternalLogin = login;
            return Task.FromResult(
                OperationResultFactory.Success(ToModel(user, now)));
        }

        private static IdentityUser<TestProfile> ToModel(
            NewIdentityUser<TestProfile> user,
            DateTimeOffset now)
            => new(
                user.Id!.Value,
                user.Flags,
                user.UserName,
                user.Email,
                false,
                user.Phone,
                false,
                user.Profile,
                1,
                user.SecurityStamp,
                null,
                null,
                null,
                now,
                now);
    }

    private sealed class FakePasswordHasher : IPasswordHasher
    {
        public int HashCount { get; private set; }

        public string HashPassword(string password)
        {
            HashCount++;
            return $"HASH:{password}";
        }

        public PasswordVerificationResult VerifyHashedPassword(
            string hashedPassword,
            string providedPassword)
            => PasswordVerificationResult.Failed;
    }

    private sealed class RecordingPasswordValidator
        : IPasswordValidator<TestProfile>
    {
        public PasswordMutation? Mutation { get; private set; }
        public long? UserVersion { get; private set; }

        public Task<OperationResult> ValidateAsync(
            PasswordValidationContext<TestProfile> context,
            CancellationToken ct)
        {
            Mutation = context.Mutation;
            UserVersion = context.User.Version;
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class RejectingPasswordValidator
        : IPasswordValidator<TestProfile>
    {
        public Task<OperationResult> ValidateAsync(
            PasswordValidationContext<TestProfile> context,
            CancellationToken ct)
            => Task.FromResult(
                OperationResultFactory.Fail(
                    new Error(
                        IdentityErrorCodes.PasswordRejected,
                        "Rejected.",
                        ErrorType.Validation)));
    }

    private sealed class FakeSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "REGISTRATION-STAMP";
    }

    public sealed record TestProfile(string DisplayName);
}
