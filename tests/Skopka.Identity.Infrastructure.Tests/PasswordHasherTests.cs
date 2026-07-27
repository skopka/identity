using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class PasswordHasherTests
{
    [Fact]
    public void Pbkdf2HashesAndVerifiesPassword()
    {
        var hasher = new Pbkdf2PasswordHasher(FastPbkdf2Options());

        var first = hasher.HashPassword("correct horse battery staple");
        var second = hasher.HashPassword("correct horse battery staple");

        Assert.NotEqual(first, second);
        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(first, "correct horse battery staple"));
        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(first, "wrong password"));
    }

    [Fact]
    public void Pbkdf2ReportsRehashWhenParametersChange()
    {
        var original = new Pbkdf2PasswordHasher(FastPbkdf2Options());
        var verifier = original.HashPassword("password");
        var upgraded = new Pbkdf2PasswordHasher(new Pbkdf2PasswordHasherOptions
        {
            Iterations = 2_000,
            MaximumAcceptedIterations = 10_000
        });

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            upgraded.VerifyHashedPassword(verifier, "password"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-verifier")]
    [InlineData("$skopka$v=1$pbkdf2-sha256$i=999999999$AA==$AA==")]
    public void Pbkdf2RejectsMalformedOrExcessiveVerifier(string verifier)
    {
        var hasher = new Pbkdf2PasswordHasher(FastPbkdf2Options());

        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(verifier, "password"));
    }

    [Fact]
    public void Argon2idHashesAndVerifiesPassword()
    {
        using var peppers = CreatePeppers("2026-01");
        var hasher = new Argon2idPepperedPasswordHasher(peppers, FastArgon2Options());

        var verifier = hasher.HashPassword("correct horse battery staple");

        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(verifier, "correct horse battery staple"));
        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(verifier, "wrong password"));
    }

    [Fact]
    public void Argon2idReportsRehashAfterPepperRotation()
    {
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);

        using var oldPeppers = new StaticPasswordPepperProvider("2026-01", oldKey);
        var original = new Argon2idPepperedPasswordHasher(oldPeppers, FastArgon2Options());
        var verifier = original.HashPassword("password");

        using var rotatedPeppers = new StaticPasswordPepperProvider(
            "2026-07",
            new Dictionary<string, byte[]>
            {
                ["2026-01"] = oldKey,
                ["2026-07"] = newKey
            });
        var rotated = new Argon2idPepperedPasswordHasher(rotatedPeppers, FastArgon2Options());

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            rotated.VerifyHashedPassword(verifier, "password"));
    }

    [Fact]
    public void Argon2idReportsRehashWhenParametersChange()
    {
        using var peppers = CreatePeppers("2026-01");
        var original = new Argon2idPepperedPasswordHasher(peppers, FastArgon2Options());
        var verifier = original.HashPassword("password");
        var upgradedOptions = FastArgon2Options();
        upgradedOptions.MemorySizeKiB = 16;
        var upgraded = new Argon2idPepperedPasswordHasher(peppers, upgradedOptions);

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            upgraded.VerifyHashedPassword(verifier, "password"));
    }

    [Fact]
    public void Argon2idFailsWhenHistoricalPepperIsUnavailable()
    {
        using var oldPeppers = CreatePeppers("2026-01");
        var original = new Argon2idPepperedPasswordHasher(oldPeppers, FastArgon2Options());
        var verifier = original.HashPassword("password");

        using var currentPeppers = CreatePeppers("2026-07");
        var current = new Argon2idPepperedPasswordHasher(currentPeppers, FastArgon2Options());

        Assert.Equal(
            PasswordVerificationResult.Failed,
            current.VerifyHashedPassword(verifier, "password"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-verifier")]
    [InlineData("$skopka$v=1$argon2id$m=999999999,t=1,p=1$kid=2026-01$AA==$AA==")]
    public void Argon2idRejectsMalformedOrExcessiveVerifier(string verifier)
    {
        using var peppers = CreatePeppers("2026-01");
        var hasher = new Argon2idPepperedPasswordHasher(peppers, FastArgon2Options());

        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(verifier, "password"));
    }

    [Fact]
    public void DependencyInjectionSelectsRequestedHasher()
    {
        var services = new ServiceCollection();
        using var peppers = CreatePeppers("2026-01");

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseArgon2idPepperedPasswordHasher(peppers, options =>
            {
                options.MemorySizeKiB = 8;
                options.Iterations = 1;
            });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<Argon2idPepperedPasswordHasher>(
            provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void DependencyInjectionCanSelectPbkdf2Hasher()
    {
        var services = new ServiceCollection();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePbkdf2PasswordHasher(options =>
            {
                options.Iterations = 1_000;
                options.MaximumAcceptedIterations = 10_000;
            });

        Assert.Contains(
            services,
            descriptor =>
                descriptor.ServiceType
                    == typeof(IPasswordCredentialService<TestProfile>)
                && descriptor.ImplementationType
                    == typeof(PasswordCredentialService<TestProfile>));
        Assert.Contains(
            services,
            descriptor =>
                descriptor.ServiceType
                    == typeof(IPasswordAuthenticationService<TestProfile>)
                && descriptor.ImplementationType
                    == typeof(PasswordAuthenticationService<TestProfile>));
        Assert.Contains(
            services,
            descriptor =>
                descriptor.ServiceType
                    == typeof(IPasswordVerificationTimingProtector)
                && descriptor.ImplementationType
                    == typeof(PasswordVerificationTimingProtector)
                && descriptor.Lifetime == ServiceLifetime.Singleton);

        using var provider = services.BuildServiceProvider();

        Assert.IsType<Pbkdf2PasswordHasher>(
            provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void LastPasswordHasherRegistrationWins()
    {
        var services = new ServiceCollection();
        using var peppers = CreatePeppers("2026-01");

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseArgon2idPepperedPasswordHasher(peppers, options =>
            {
                options.MemorySizeKiB = 8;
                options.Iterations = 1;
            })
            .UsePbkdf2PasswordHasher(options =>
            {
                options.Iterations = 1_000;
                options.MaximumAcceptedIterations = 10_000;
            });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<Pbkdf2PasswordHasher>(
            provider.GetRequiredService<IPasswordHasher>());
        Assert.Null(provider.GetService<Argon2idPepperedPasswordHasherOptions>());
    }

    [Fact]
    public void DependencyInjectionResolvesPasswordAuthenticationService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<
            IIdentityUserLookupStore<TestProfile>,
            EmptyUserLookupStore>();
        services.AddSingleton<
            IPasswordCredentialStore<TestProfile>,
            EmptyPasswordCredentialStore>();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UsePbkdf2PasswordHasher(options =>
            {
                options.Iterations = 1_000;
                options.MaximumAcceptedIterations = 10_000;
            });

        using var provider = services.BuildServiceProvider();

        Assert.IsType<PasswordAuthenticationService<TestProfile>>(
            provider.GetRequiredService<
                IPasswordAuthenticationService<TestProfile>>());
    }

    public sealed record TestProfile(string DisplayName);

    private static Pbkdf2PasswordHasherOptions FastPbkdf2Options()
        => new()
        {
            Iterations = 1_000,
            MaximumAcceptedIterations = 10_000
        };

    private static Argon2idPepperedPasswordHasherOptions FastArgon2Options()
        => new()
        {
            MemorySizeKiB = 8,
            Iterations = 1,
            DegreeOfParallelism = 1,
            MaximumAcceptedMemorySizeKiB = 1_024,
            MaximumAcceptedIterations = 4
        };

    private static StaticPasswordPepperProvider CreatePeppers(string keyId)
        => new(keyId, RandomNumberGenerator.GetBytes(32));

    private sealed class EmptyUserLookupStore
        : IIdentityUserLookupStore<TestProfile>
    {
        public Task<IdentityUser<TestProfile>?> FindActiveByNormalizedUserNameAsync(
            string normalizedUserName,
            CancellationToken ct)
            => Task.FromResult<IdentityUser<TestProfile>?>(null);

        public Task<IdentityUser<TestProfile>?> FindActiveByNormalizedEmailAsync(
            string normalizedEmail,
            CancellationToken ct)
            => Task.FromResult<IdentityUser<TestProfile>?>(null);
    }

    private sealed class EmptyPasswordCredentialStore
        : IPasswordCredentialStore<TestProfile>
    {
        public Task<string?> FindPasswordVerifierAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult<string?>(null);

        public Task<OperationResult> ReplacePasswordVerifierAsync(
            Guid userId,
            long expectedVersion,
            string? expectedPasswordVerifier,
            string? passwordVerifier,
            DateTimeOffset now,
            CancellationToken ct)
            => Task.FromResult(OperationResultFactory.Success());
    }
}
