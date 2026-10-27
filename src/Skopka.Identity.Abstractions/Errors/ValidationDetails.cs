namespace Skopka.Identity.Errors;

public sealed record ValidationDetails(IReadOnlyDictionary<string, string[]> Fields)
{
    public IReadOnlyList<string>? AllowedPhoneCountryCodes { get; init; }
}
