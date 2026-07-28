namespace Skopka.Identity.Verification;

public enum VerificationChallengeState
{
    Pending = 0,
    Verified = 1,
    Consumed = 2,
    Locked = 3,
}
