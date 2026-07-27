namespace Skopka.Identity.Authentication;

public interface IPasswordVerificationTimingProtector
{
    void SimulateVerification(string providedPassword);
}
