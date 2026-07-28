namespace Skopka.Identity.Verification;

public sealed record IssuedVerificationMethodChallenge(
    string Verifier,
    string? DeliveryCode);
