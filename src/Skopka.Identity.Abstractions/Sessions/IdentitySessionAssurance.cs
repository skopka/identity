namespace Skopka.Identity.Sessions;

/// <summary>Trusted server assertion about the additional factor verified for a logical session.</summary>
public enum IdentitySessionAssurance
{
    /// <summary>No additional factor is asserted, including legacy sessions.</summary>
    None = 0,
    /// <summary>A TOTP factor or its recovery code was verified.</summary>
    TotpVerified = 1,
}
