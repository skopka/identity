using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Skopka.Identity.Sessions;

public sealed class HmacJwtAccessTokenProvider
    : IIdentityAccessTokenProvider, IDisposable
{
    private const string LegacyKeyId = "legacy";

    private readonly IReadOnlyDictionary<string, byte[]> signingKeys;
    private readonly JsonWebTokenHandler handler;
    private readonly SigningCredentials signingCredentials;
    private readonly TokenValidationParameters validationParameters;
    private readonly string issuer;
    private readonly string audience;
    private bool disposed;

    public HmacJwtAccessTokenProvider(
        byte[] signingKey,
        JwtAccessTokenOptions options)
        : this(
            currentKeyId: null,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [LegacyKeyId] = signingKey,
            },
            options,
            versioned: false)
    {
    }

    public HmacJwtAccessTokenProvider(
        string currentKeyId,
        IReadOnlyDictionary<string, byte[]> signingKeys,
        JwtAccessTokenOptions options)
        : this(
            currentKeyId,
            signingKeys,
            options,
            versioned: true)
    {
    }

    private HmacJwtAccessTokenProvider(
        string? currentKeyId,
        IReadOnlyDictionary<string, byte[]> signingKeys,
        JwtAccessTokenOptions options,
        bool versioned)
    {
        ArgumentNullException.ThrowIfNull(signingKeys);
        ArgumentNullException.ThrowIfNull(options);

        if (signingKeys.Count is < 1
            or > SessionLimits.MaximumJwtSigningKeys)
        {
            throw new ArgumentException(
                $"Between 1 and {SessionLimits.MaximumJwtSigningKeys} JWT signing keys must be configured.",
                nameof(signingKeys));
        }

        if (versioned)
        {
            ValidateKeyId(currentKeyId, nameof(currentKeyId));
        }

        var copiedKeys = new Dictionary<string, byte[]>(
            signingKeys.Count,
            StringComparer.Ordinal);
        try
        {
            foreach (var (keyId, signingKey) in signingKeys)
            {
                if (versioned)
                {
                    ValidateKeyId(keyId, nameof(signingKeys));
                }

                ArgumentNullException.ThrowIfNull(signingKey);
                if (signingKey.Length
                    < SessionLimits.MinimumJwtSigningKeyLength)
                {
                    throw new ArgumentException(
                        $"Each JWT signing key must contain at least {SessionLimits.MinimumJwtSigningKeyLength} bytes.",
                        nameof(signingKeys));
                }

                copiedKeys.Add(keyId, signingKey.ToArray());
            }

            if (versioned && !copiedKeys.ContainsKey(currentKeyId!))
            {
                throw new ArgumentException(
                    "The current JWT signing key id is not present in the key collection.",
                    nameof(currentKeyId));
            }
        }
        catch
        {
            foreach (var copiedKey in copiedKeys.Values)
            {
                CryptographicOperations.ZeroMemory(copiedKey);
            }

            throw;
        }

        this.signingKeys = copiedKeys;
        issuer = options.Issuer;
        audience = options.Audience;
        var securityKeys = copiedKeys
            .Select(pair =>
            {
                var securityKey = new SymmetricSecurityKey(pair.Value);
                if (versioned)
                {
                    securityKey.KeyId = pair.Key;
                }

                return securityKey;
            })
            .ToArray();
        var securityKeysById = securityKeys
            .Where(key => key.KeyId is not null)
            .ToDictionary(
                key => key.KeyId!,
                key => (SecurityKey)key,
                StringComparer.Ordinal);
        var currentSecurityKey = versioned
            ? securityKeysById[currentKeyId!]
            : securityKeys[0];
        signingCredentials = new SigningCredentials(
            currentSecurityKey,
            SecurityAlgorithms.HmacSha256);
        validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = securityKeys,
            IssuerSigningKeyResolver = (_, _, keyId, _) =>
                string.IsNullOrEmpty(keyId)
                    ? securityKeys
                    : securityKeysById.TryGetValue(
                        keyId,
                        out var resolvedKey)
                        ? [resolvedKey]
                        : [],
            TryAllIssuerSigningKeys = false,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = options.ClockSkew,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidTypes = ["JWT"],
        };
        handler = new JsonWebTokenHandler
        {
            MaximumTokenSizeInBytes = SessionLimits.MaximumTokenLength,
            SetDefaultTimesOnTokenCreation = false,
        };
    }

    public string Generate(IdentityAccessTokenPayload payload)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(payload);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = payload.IssuedAt.UtcDateTime,
            NotBefore = payload.IssuedAt.UtcDateTime,
            Expires = payload.ExpiresAt.UtcDateTime,
            SigningCredentials = signingCredentials,
            Subject = new ClaimsIdentity(
                (payload.Claims ?? [])
                    .Select(CreateClaim)),
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = payload.UserId.ToString("N"),
                [JwtRegisteredClaimNames.Jti] = payload.TokenId.ToString("N"),
                [IdentitySessionClaimTypes.SessionId] =
                    payload.SessionId.ToString("N"),
                [IdentitySessionClaimTypes.FormatVersion] =
                    payload.FormatVersion,
            },
        };

        var token = handler.CreateToken(descriptor);
        if (token.Length > SessionLimits.MaximumTokenLength)
        {
            throw new InvalidOperationException(
                "The generated access token exceeds the supported length.");
        }

        return token;
    }

    public async Task<IdentityAccessTokenPayload?> ValidateAsync(
        string token,
        CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(token)
            || token.Length > SessionLimits.MaximumTokenLength)
        {
            return null;
        }

        var result = await handler.ValidateTokenAsync(
            token,
            validationParameters);
        if (!result.IsValid
            || result.SecurityToken is not JsonWebToken jwt
            || !TryReadGuid(jwt, JwtRegisteredClaimNames.Jti, out var tokenId)
            || !TryReadGuid(jwt, JwtRegisteredClaimNames.Sub, out var userId)
            || !TryReadGuid(
                jwt,
                IdentitySessionClaimTypes.SessionId,
                out var sessionId)
            || !jwt.TryGetPayloadValue<int>(
                IdentitySessionClaimTypes.FormatVersion,
                out var formatVersion))
        {
            return null;
        }

        return new IdentityAccessTokenPayload(
            formatVersion,
            tokenId,
            userId,
            sessionId,
            new DateTimeOffset(jwt.ValidFrom, TimeSpan.Zero),
            new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero),
            result.ClaimsIdentity.Claims
                .Where(claim => !ReservedClaimTypes.Contains(claim.Type))
                .Select(claim => new IdentitySessionClaim(
                    claim.Type,
                    claim.Value))
                .ToArray());
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        foreach (var signingKey in signingKeys.Values)
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }

    internal TokenValidationParameters CreateTokenValidationParameters()
        => validationParameters.Clone();

    private static bool TryReadGuid(
        JsonWebToken jwt,
        string claim,
        out Guid value)
    {
        value = default;
        return jwt.TryGetPayloadValue<string>(claim, out var text)
            && Guid.TryParseExact(text, "N", out value);
    }

    private static void ValidateKeyId(
        string? keyId,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(keyId)
            || keyId.Length > SessionLimits.MaximumJwtSigningKeyIdLength
            || keyId.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
        {
            throw new ArgumentException(
                "JWT signing key ids must contain only ASCII letters, digits, '.', '_' or '-'.",
                parameterName);
        }
    }

    private static Claim CreateClaim(IdentitySessionClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        if (string.IsNullOrWhiteSpace(claim.Type)
            || claim.Type.Length
                > IdentitySessionClaimLimits.MaximumTypeLength
            || claim.Value is null
            || claim.Value.Length
                > IdentitySessionClaimLimits.MaximumValueLength
            || ReservedClaimTypes.Contains(claim.Type))
        {
            throw new ArgumentException(
                "The access token contains an invalid custom claim.",
                nameof(claim));
        }

        var valueType = claim.Type is
            IdentitySessionClaimTypes.EmailVerified
            or IdentitySessionClaimTypes.PhoneNumberVerified
                ? ClaimValueTypes.Boolean
                : ClaimValueTypes.String;

        return new Claim(
            claim.Type,
            claim.Value,
            valueType);
    }

    private static readonly HashSet<string> ReservedClaimTypes =
        new(StringComparer.Ordinal)
        {
            JwtRegisteredClaimNames.Iss,
            JwtRegisteredClaimNames.Aud,
            JwtRegisteredClaimNames.Exp,
            JwtRegisteredClaimNames.Nbf,
            JwtRegisteredClaimNames.Iat,
            JwtRegisteredClaimNames.Jti,
            JwtRegisteredClaimNames.Sub,
            IdentitySessionClaimTypes.SessionId,
            IdentitySessionClaimTypes.FormatVersion,
        };
}
