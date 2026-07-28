namespace Skopka.Identity;

public interface IProfilePatch<in TProfile>
{
    void ApplyTo(TProfile profile);
}