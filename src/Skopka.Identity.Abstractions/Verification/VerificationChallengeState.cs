namespace Skopka.Identity.Verification;

public enum VerificationChallengeState
{
    Pending = 0,
    Verified = 1,
    Consumed = 2,
    Locked = 3,
    /// <summary>
    /// A newer challenge for the same exact verification intent replaced this one.
    /// </summary>
    Superseded = 4,
}
