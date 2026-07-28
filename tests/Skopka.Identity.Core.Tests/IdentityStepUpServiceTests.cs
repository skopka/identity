using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.StepUp;
using Skopka.Identity.StepUp.Commands;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityStepUpServiceTests
{
    private const string Action = "payments.approve";
    private const string Binding = "payment:42";
    private const string Purpose = "step-up:payments.approve";

    [Fact]
    public async Task BeginUsesPolicyPurposeAndIntentBinding()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.BeginAsync(
            new BeginStepUpCommand(
                fixture.UserId,
                Action,
                Binding,
                VerificationMethods.OneTimeCode,
                "client"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        var command = Assert.IsType<BeginVerificationCommand>(
            fixture.Verification.LastBeginCommand);
        Assert.Equal(Purpose, command.Purpose);
        Assert.Equal(IntentBinding(Action, Binding), command.Binding);
        Assert.Equal(VerificationMethods.OneTimeCode, command.Method);
        Assert.Equal("client", command.ClientKey);
        Assert.Equal(
            new StepUpAuthorizationContext(
                fixture.UserId,
                Action,
                Binding),
            fixture.Policy.LastContext);
    }

    [Fact]
    public async Task BeginRejectsMethodNotAllowedByPolicy()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.BeginAsync(
            new BeginStepUpCommand(
                fixture.UserId,
                Action,
                Binding,
                "webauthn"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.StepUpMethodNotAllowed);
        Assert.Null(fixture.Verification.LastBeginCommand);
    }

    [Fact]
    public async Task BeginRejectsActionWithoutPolicy()
    {
        var fixture = new Fixture(policyAvailable: false);

        var result = await fixture.Service.BeginAsync(
            new BeginStepUpCommand(
                fixture.UserId,
                Action,
                Binding,
                VerificationMethods.OneTimeCode),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.StepUpPolicyUnavailable);
        Assert.Null(fixture.Verification.LastBeginCommand);
    }

    [Fact]
    public async Task AuthorizeConsumesProofAndReturnsDecisionMetadata()
    {
        var fixture = new Fixture();
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge();

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(fixture.UserId, result.Value.UserId);
        Assert.Equal(Action, result.Value.Action);
        Assert.Equal(Binding, result.Value.Binding);
        Assert.Equal(Purpose, result.Value.Purpose);
        Assert.Equal(fixture.Store.Challenge.Id, result.Value.ChallengeId);
        Assert.Equal(2, result.Value.AssuranceLevel);
        Assert.Equal(
            fixture.Store.Challenge.VerifiedAt,
            result.Value.VerifiedAt);

        var consume = Assert.IsType<ConsumeVerificationProofCommand>(
            fixture.Verification.LastConsumeCommand);
        Assert.Equal(Purpose, consume.Purpose);
        Assert.Equal(IntentBinding(Action, Binding), consume.Binding);
        Assert.Equal("proof-token", consume.Proof);
    }

    [Fact]
    public async Task AuthorizeRejectsDifferentResourceBindingWithoutConsume()
    {
        var fixture = new Fixture();
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge();

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(binding: "payment:43"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Null(fixture.Verification.LastConsumeCommand);
    }

    [Fact]
    public async Task AuthorizeRejectsDifferentActionWithSharedPolicyPurpose()
    {
        var fixture = new Fixture();
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge();

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(action: "payments.cancel"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Null(fixture.Verification.LastConsumeCommand);
    }

    [Fact]
    public async Task AuthorizeAppliesCurrentMethodPolicyBeforeConsume()
    {
        var fixture = new Fixture();
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge();
        fixture.Policy.Requirement = new StepUpRequirement(
            Purpose,
            ["webauthn"],
            AssuranceLevel: 3);

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.StepUpMethodNotAllowed);
        Assert.Null(fixture.Verification.LastConsumeCommand);
    }

    [Fact]
    public async Task AuthorizeRejectsProofOlderThanPolicyMaximumAge()
    {
        var requirement = new StepUpRequirement(
            Purpose,
            [VerificationMethods.OneTimeCode],
            AssuranceLevel: 2,
            MaximumAge: TimeSpan.FromSeconds(10));
        var fixture = new Fixture(requirement);
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge(
            verifiedAt: DateTimeOffset.UtcNow.AddMinutes(-1));

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Null(fixture.Verification.LastConsumeCommand);
    }

    [Fact]
    public async Task AuthorizeDoesNotIssueDecisionWhenConsumeFails()
    {
        var fixture = new Fixture();
        fixture.Store.Challenge = fixture.CreateVerifiedChallenge();
        fixture.Verification.ConsumeResult = OperationResultFactory.Fail(
            new Error(
                IdentityErrorCodes.ConcurrencyConflict,
                "Concurrency conflict.",
                ErrorType.Conflict));

        var result = await fixture.Service.AuthorizeAsync(
            fixture.AuthorizeCommand(),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
    }

    [Fact]
    public async Task InvalidPolicyConfigurationFailsFast()
    {
        var fixture = new Fixture(
            new StepUpRequirement(
                Purpose,
                [],
                AssuranceLevel: 2));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Service.BeginAsync(
                new BeginStepUpCommand(
                    fixture.UserId,
                    Action,
                    Binding,
                    VerificationMethods.OneTimeCode),
                CancellationToken.None));
    }

    private static void AssertError(OperationResult result, string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class Fixture
    {
        public Fixture(
            StepUpRequirement? requirement = null,
            bool policyAvailable = true)
        {
            UserId = Guid.NewGuid();
            Verification = new FakeVerificationService();
            Store = new FakeChallengeStore();
            var effectiveRequirement = policyAvailable
                ? requirement ?? new StepUpRequirement(
                    Purpose,
                    [VerificationMethods.OneTimeCode],
                    AssuranceLevel: 2,
                    MaximumAge: TimeSpan.FromMinutes(1))
                : null;
            Policy = new FakePolicyProvider(effectiveRequirement);
            Service = new IdentityStepUpService<TestProfile>(
                Verification,
                Store,
                Policy,
                new NoopIdentityMetrics());
        }

        public Guid UserId { get; }
        public FakeVerificationService Verification { get; }
        public FakeChallengeStore Store { get; }
        public FakePolicyProvider Policy { get; }
        public IdentityStepUpService<TestProfile> Service { get; }

        public AuthorizeStepUpCommand AuthorizeCommand(
            string action = Action,
            string binding = Binding)
            => new(
                UserId,
                action,
                binding,
                Store.Challenge?.Id ?? Guid.NewGuid(),
                "proof-token");

        public StoredVerificationChallenge CreateVerifiedChallenge(
            DateTimeOffset? verifiedAt = null)
        {
            var now = DateTimeOffset.UtcNow;
            return new StoredVerificationChallenge(
                Guid.NewGuid(),
                UserId,
                Purpose,
                IntentBinding(Action, Binding),
                VerificationMethods.OneTimeCode,
                "verifier",
                "security-stamp",
                0,
                5,
                VerificationChallengeState.Verified,
                "proof-hash",
                now.AddMinutes(1),
                2,
                now.AddMinutes(2),
                now.AddMinutes(-1),
                now,
                verifiedAt ?? now.AddSeconds(-1),
                null);
        }
    }

    private static string IntentBinding(
        string action,
        string resourceBinding)
    {
        var value = $"step-up:v1|{action.Length}:{action}|"
            + $"{resourceBinding.Length}:{resourceBinding}";
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private sealed class FakePolicyProvider(StepUpRequirement? requirement)
        : IStepUpPolicyProvider<TestProfile>
    {
        public StepUpRequirement? Requirement { get; set; } = requirement;
        public StepUpAuthorizationContext? LastContext { get; private set; }

        public Task<StepUpRequirement?> GetRequirementAsync(
            StepUpAuthorizationContext context,
            CancellationToken ct)
        {
            LastContext = context;
            return Task.FromResult(Requirement);
        }
    }

    private sealed class FakeVerificationService
        : IIdentityVerificationService<TestProfile>
    {
        public BeginVerificationCommand? LastBeginCommand { get; private set; }
        public ConsumeVerificationProofCommand? LastConsumeCommand
        {
            get;
            private set;
        }

        public OperationResult ConsumeResult { get; set; } =
            OperationResultFactory.Success();

        public Task<OperationResult<IssuedVerificationChallenge>> BeginAsync(
            BeginVerificationCommand cmd,
            CancellationToken ct)
        {
            LastBeginCommand = cmd;
            return Task.FromResult(
                OperationResultFactory.Success(
                    new IssuedVerificationChallenge(
                        Guid.NewGuid(),
                        cmd.Method,
                        DateTimeOffset.UtcNow.AddMinutes(5),
                        "123456")));
        }

        public Task<OperationResult<VerificationProof>> VerifyAsync(
            VerifyVerificationChallengeCommand cmd,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> ConsumeAsync(
            ConsumeVerificationProofCommand cmd,
            CancellationToken ct)
        {
            LastConsumeCommand = cmd;
            return Task.FromResult(ConsumeResult);
        }
    }

    private sealed class FakeChallengeStore
        : IVerificationChallengeStore<TestProfile>
    {
        public StoredVerificationChallenge? Challenge { get; set; }

        public Task<StoredVerificationChallenge?> FindByIdAsync(
            Guid challengeId,
            CancellationToken ct)
            => Task.FromResult(
                Challenge?.Id == challengeId ? Challenge : null);

        public Task<OperationResult> CreateAsync(
            NewVerificationChallenge challenge,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<StoredVerificationChallenge>>
            RecordAttemptAsync(
                Guid challengeId,
                long expectedVersion,
                bool succeeded,
                string? proofHash,
                DateTimeOffset? proofExpiresAt,
                DateTimeOffset now,
                CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> ConsumeProofAsync(
            Guid challengeId,
            long expectedVersion,
            Guid userId,
            string purpose,
            string binding,
            string proofHash,
            string securityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    public sealed record TestProfile(string DisplayName);
}
