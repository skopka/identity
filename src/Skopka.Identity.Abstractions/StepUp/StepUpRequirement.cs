namespace Skopka.Identity.StepUp;

// AssuranceLevel is an application-defined ordinal, not a standards compliance claim.
public sealed record StepUpRequirement(
    string Purpose,
    IReadOnlyCollection<string> AllowedMethods,
    int AssuranceLevel,
    TimeSpan? MaximumAge = null);
