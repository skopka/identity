namespace Skopka.Identity.PhoneOtp;

public sealed class PhoneOtpOptions
{
    public int DailyPhonePermitLimit { get; set; } = 10;
    public int DailyClientPermitLimit { get; set; } = 100;
    public TimeSpan DailyWindow { get; set; } = TimeSpan.FromDays(1);
    public IReadOnlyList<string> AllowedCountryCodes { get; set; } = [];
}
