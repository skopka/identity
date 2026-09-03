using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Security;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.WebAuthn;
using Xunit;

namespace Skopka.Identity.Core.Tests;

/// <summary>
/// The ceremonies themselves are the verifier's, and are tested against a
/// software authenticator in the infrastructure tests. What is tested here is
/// what the service adds around them: whose credential it is, how many may
/// exist, what a replayed assertion does, and what removing one costs.
/// </summary>
public sealed class IdentityWebAuthnServiceTests
{
    private static readonly byte[] Challenge = new byte[32];

    [Fact]
    public async Task RegistersAVerifiedCredential()
    {
        var world = new World();

        var registered = await world.Service.RegisterAsync(
            Register(world.UserId, "Ключ на ноутбуке"),
            CancellationToken.None);

        Assert.True(registered.IsSuccess);
        Assert.Equal("Ключ на ноутбуке", registered.Value.Label);
        Assert.Single(world.Credentials.Rows);
    }

    /// <summary>
    /// The verifier is called by the service, so a caller cannot persist a key
    /// by forgetting to check the ceremony that delivered it.
    /// </summary>
    [Fact]
    public async Task KeepsNothingWhenTheCeremonyFails()
    {
        var world = new World();
        world.Verifier.Accept = false;

        var registered = await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None);

        Assert.Contains(
            registered.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnSignatureInvalid);
        Assert.Empty(world.Credentials.Rows);
    }

    [Fact]
    public async Task RefusesMoreCredentialsThanAllowed()
    {
        var world = new World(maximumCredentials: 1);
        Assert.True((await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None)).IsSuccess);
        world.Verifier.CredentialId = [.. Enumerable.Repeat((byte)0x77, 32)];

        var second = await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None);

        Assert.Contains(
            second.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnTooManyCredentials);
    }

    /// <summary>
    /// No handle is asked for, and none is needed: the credential names its
    /// owner.
    /// </summary>
    [Fact]
    public async Task FindsTheOwnerOfAnAcceptedAssertion()
    {
        var world = new World();
        Assert.True((await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None)).IsSuccess);
        world.Verifier.Counter = 1;

        var authenticated = await world.Service.AuthenticateAsync(
            Authenticate(world.Verifier.CredentialId),
            CancellationToken.None);

        Assert.True(authenticated.IsSuccess);
        Assert.Equal(world.UserId, authenticated.Value.Id);
        Assert.Equal(1, world.Credentials.Rows[0].SignatureCounter);
        Assert.NotNull(world.Credentials.Rows[0].LastUsedAt);
    }

    /// <summary>
    /// Whether a credential id is known is not something an unauthenticated
    /// caller may learn, so an unknown one answers exactly as a bad signature
    /// does.
    /// </summary>
    [Fact]
    public async Task AnswersAnUnknownCredentialAsABadSignature()
    {
        var world = new World();

        var authenticated = await world.Service.AuthenticateAsync(
            Authenticate([.. Enumerable.Repeat((byte)0x99, 32)]),
            CancellationToken.None);

        Assert.Contains(
            authenticated.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnSignatureInvalid);
    }

    /// <summary>
    /// Two sign-ins from one assertion is one too many. The counter is written
    /// under the version that was read, so the second attempt finds the row
    /// moved and gets nothing.
    /// </summary>
    [Fact]
    public async Task LetsOneAssertionSignInOnce()
    {
        var world = new World();
        Assert.True((await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None)).IsSuccess);
        world.Verifier.Counter = 1;
        world.Credentials.RefuseAdvance = true;

        var authenticated = await world.Service.AuthenticateAsync(
            Authenticate(world.Verifier.CredentialId),
            CancellationToken.None);

        Assert.Contains(
            authenticated.Errors,
            error => error.Code == IdentityErrorCodes.WebAuthnSignatureInvalid);
    }

    [Fact]
    public async Task RefusesAnAssertionForABlockedUser()
    {
        var world = new World(blocked: true);
        world.Credentials.Rows.Add(new StoredWebAuthnCredential(
            Guid.NewGuid(),
            world.UserId,
            world.Verifier.CredentialId,
            [1],
            WebAuthnAlgorithm.Es256,
            0,
            Guid.Empty,
            BackedUp: false,
            Label: null,
            Version: 1,
            CreatedAt: DateTimeOffset.UnixEpoch,
            LastUsedAt: null));

        var authenticated = await world.Service.AuthenticateAsync(
            Authenticate(world.Verifier.CredentialId),
            CancellationToken.None);

        Assert.Contains(
            authenticated.Errors,
            error => error.Code == IdentityErrorCodes.AuthenticationBlocked);
    }

    /// <summary>
    /// A credential that is gone must not go on signing in through a session
    /// issued while it was there.
    /// </summary>
    [Fact]
    public async Task RotatesTheStampWhenACredentialIsRemoved()
    {
        var world = new World();
        Assert.True((await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None)).IsSuccess);
        var credentialId = world.Credentials.Rows[0].Id;

        var removed = await world.Service.RemoveAsync(
            new RemoveWebAuthnCredentialCommand(world.UserId, credentialId, 7),
            CancellationToken.None);

        Assert.True(removed.IsSuccess);
        Assert.Empty(world.Credentials.Rows);
        Assert.Equal(1, world.Stamps.Rotations);
    }

    [Fact]
    public async Task RefusesToRemoveAgainstAStaleVersion()
    {
        var world = new World();
        Assert.True((await world.Service.RegisterAsync(
            Register(world.UserId),
            CancellationToken.None)).IsSuccess);

        var removed = await world.Service.RemoveAsync(
            new RemoveWebAuthnCredentialCommand(
                world.UserId,
                world.Credentials.Rows[0].Id,
                6),
            CancellationToken.None);

        Assert.Contains(
            removed.Errors,
            error => error.Code == IdentityErrorCodes.ConcurrencyConflict);
        Assert.Single(world.Credentials.Rows);
        Assert.Equal(0, world.Stamps.Rotations);
    }

    private static RegisterWebAuthnCredentialCommand Register(
        Guid userId,
        string? label = null)
        => new(userId, [1], [2], Challenge, label);

    private static AuthenticateWebAuthnCommand Authenticate(byte[] credentialId)
        => new(credentialId, [1], [2], [3], Challenge);

    private sealed record TestProfile(string DisplayName);

    private sealed class World
    {
        public World(int maximumCredentials = 10, bool blocked = false)
        {
            UserId = Guid.NewGuid();
            var user = new IdentityUser<TestProfile>(
                UserId,
                UserFlags.None,
                "alice",
                "alice@example.test",
                true,
                null,
                false,
                new TestProfile("Alice"),
                7,
                "CURRENT-STAMP",
                null,
                blocked ? DateTimeOffset.UnixEpoch : null,
                null,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch);
            var options = new WebAuthnOptions
            {
                RelyingPartyId = "skopi.club",
                MaximumCredentialsPerUser = maximumCredentials,
            };
            options.Origins.Add("https://skopi.club");
            Stamps = new FakeStamps(user);
            Service = new IdentityWebAuthnService<TestProfile>(
                Credentials,
                new FakeUserStore(user),
                Verifier,
                Stamps,
                options,
                new IdentityRateLimitOptions(),
                [],
                new NoopIdentityMetrics());
        }

        public Guid UserId { get; }

        public FakeCredentialStore Credentials { get; } = new();

        public FakeVerifier Verifier { get; } = new();

        public FakeStamps Stamps { get; }

        public IIdentityWebAuthnService<TestProfile> Service { get; }
    }

    private sealed class FakeVerifier : IWebAuthnCeremonyVerifier
    {
        public bool Accept { get; set; } = true;

        public long Counter { get; set; }

        public byte[] CredentialId { get; set; } =
            [.. Enumerable.Repeat((byte)0x11, 32)];

        public OperationResult<WebAuthnAttestedCredential> ReadRegistration(
            ReadOnlyMemory<byte> clientDataJson,
            ReadOnlyMemory<byte> attestationObject,
            WebAuthnCeremonyExpectation expectation)
            => Accept
                ? OperationResultFactory.Success(new WebAuthnAttestedCredential(
                    CredentialId,
                    new byte[] { 9 },
                    WebAuthnAlgorithm.Es256,
                    Counter,
                    Guid.Empty,
                    UserVerified: true,
                    BackedUp: false))
                : OperationResultFactory.Fail<WebAuthnAttestedCredential>(
                    Rejected());

        public OperationResult<WebAuthnAssertionOutcome> VerifyAssertion(
            ReadOnlyMemory<byte> clientDataJson,
            ReadOnlyMemory<byte> authenticatorData,
            ReadOnlyMemory<byte> signature,
            WebAuthnAssertionExpectation expectation)
            => Accept
                ? OperationResultFactory.Success(new WebAuthnAssertionOutcome(
                    Counter,
                    UserVerified: true,
                    BackedUp: false))
                : OperationResultFactory.Fail<WebAuthnAssertionOutcome>(Rejected());

        private static Error Rejected()
            => new(
                IdentityErrorCodes.WebAuthnSignatureInvalid,
                "Rejected.",
                ErrorType.Unauthorized);
    }

    private sealed class FakeCredentialStore : IWebAuthnCredentialStore<TestProfile>
    {
        public List<StoredWebAuthnCredential> Rows { get; } = [];

        public bool RefuseAdvance { get; set; }

        public Task<StoredWebAuthnCredential?> FindByCredentialIdAsync(
            byte[] credentialId,
            CancellationToken ct)
            => Task.FromResult(Rows.FirstOrDefault(
                row => row.CredentialId.SequenceEqual(credentialId)));

        public Task<IReadOnlyList<StoredWebAuthnCredential>> ListByUserIdAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult<IReadOnlyList<StoredWebAuthnCredential>>(
                [.. Rows.Where(row => row.UserId == userId)]);

        public Task<OperationResult> CreateAsync(
            NewWebAuthnCredential credential,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Rows.Add(new StoredWebAuthnCredential(
                credential.Id,
                credential.UserId,
                credential.CredentialId,
                credential.PublicKey,
                credential.Algorithm,
                credential.SignatureCounter,
                credential.AuthenticatorId,
                credential.BackedUp,
                credential.Label,
                1,
                now,
                null));
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult<bool>> TryAdvanceCounterAsync(
            Guid id,
            long expectedVersion,
            long counter,
            DateTimeOffset usedAt,
            CancellationToken ct)
        {
            if (RefuseAdvance)
            {
                return Task.FromResult(OperationResultFactory.Success(false));
            }

            var index = Rows.FindIndex(row => row.Id == id);
            Rows[index] = Rows[index] with
            {
                SignatureCounter = counter,
                LastUsedAt = usedAt,
                Version = expectedVersion + 1,
            };
            return Task.FromResult(OperationResultFactory.Success(true));
        }

        public Task<OperationResult> RemoveAsync(
            Guid userId,
            Guid id,
            CancellationToken ct)
        {
            Rows.RemoveAll(row => row.Id == id && row.UserId == userId);
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakeStamps(IdentityUser<TestProfile> user)
        : ISecurityStampService<TestProfile>
    {
        public int Rotations { get; private set; }

        public Task<OperationResult<IdentityUser<TestProfile>>> RotateAsync(
            RotateSecurityStampCommand cmd,
            CancellationToken ct)
        {
            Rotations++;
            return Task.FromResult(OperationResultFactory.Success(
                user with { SecurityStamp = "NEXT-STAMP" }));
        }

        public Task<bool> ValidateAsync(
            Guid userId,
            string securityStamp,
            CancellationToken ct)
            => Task.FromResult(true);
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == user.Id ? user : null);

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
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(
            Guid userId,
            long expectedVersion,
            TestProfile profile,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateSecurityStampAsync(
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
}
