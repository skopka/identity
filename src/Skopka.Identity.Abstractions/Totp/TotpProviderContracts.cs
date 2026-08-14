namespace Skopka.Identity.Totp;

public interface ITotpCodeProvider
{
    string CreateSecret();

    bool TryMatchCounter(
        string secret,
        string response,
        DateTimeOffset now,
        long? minimumExclusiveCounter,
        out long counter);
}

public interface ITotpSecretProtector
{
    string Protect(string secret);

    bool TryUnprotect(string protectedSecret, out string secret);
}
