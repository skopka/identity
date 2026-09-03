using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.WebAuthn;

namespace Skopka.Identity.Infrastructure.WebAuthn;

/// <summary>
/// Reads and checks the two WebAuthn ceremonies against what the server
/// expected.
///
/// Attestation statements are read but not verified. Deciding that a particular
/// authenticator model made a key means holding a trusted metadata set and a
/// policy about which models are acceptable, which belongs to an application
/// rather than to an identity library; the specification calls attestation
/// optional and expects most relying parties to skip it. What is verified is
/// everything that makes a credential this server's own: the relying party, the
/// origin, the challenge, user presence, and the signature.
/// </summary>
public sealed class WebAuthnCeremonyVerifier : IWebAuthnCeremonyVerifier
{
    private const string CreateCeremony = "webauthn.create";
    private const string GetCeremony = "webauthn.get";

    private const byte UserPresentFlag = 0b0000_0001;
    private const byte UserVerifiedFlag = 0b0000_0100;
    private const byte BackedUpFlag = 0b0001_0000;
    private const byte AttestedCredentialFlag = 0b0100_0000;

    /// <summary>
    /// Relying party hash, flags and counter. Everything after it is present
    /// only when a flag says so.
    /// </summary>
    private const int HeaderLength = 37;

    private const int AaGuidLength = 16;
    private const int CredentialIdPrefixLength = 2;

    public OperationResult<WebAuthnAttestedCredential> ReadRegistration(
        ReadOnlyMemory<byte> clientDataJson,
        ReadOnlyMemory<byte> attestationObject,
        WebAuthnCeremonyExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        if (attestationObject.Length is 0
            or > WebAuthnLimits.MaximumAttestationObjectLength)
        {
            return Fail<WebAuthnAttestedCredential>(
                WebAuthnErrors.AttestationInvalid());
        }

        var clientData = ReadClientData(clientDataJson, CreateCeremony, expectation);
        if (!clientData.IsSuccess)
        {
            return OperationResultFactory.Fail<WebAuthnAttestedCredential>(
                clientData.Errors);
        }

        if (!TryReadAttestation(attestationObject, out var authenticatorData))
        {
            return Fail<WebAuthnAttestedCredential>(
                WebAuthnErrors.AttestationInvalid());
        }

        var header = ReadAuthenticatorData(authenticatorData, expectation);
        if (!header.IsSuccess)
        {
            return OperationResultFactory.Fail<WebAuthnAttestedCredential>(
                header.Errors);
        }

        var flags = header.Value.Flags;
        if ((flags & AttestedCredentialFlag) == 0
            || !TryReadAttestedCredential(
                authenticatorData,
                out var authenticatorId,
                out var credentialId,
                out var coseKey))
        {
            return Fail<WebAuthnAttestedCredential>(
                WebAuthnErrors.AttestationInvalid());
        }

        if (!TryReadPublicKey(coseKey, out var algorithm, out var publicKey))
        {
            return Fail<WebAuthnAttestedCredential>(
                WebAuthnErrors.AlgorithmNotSupported());
        }

        return OperationResultFactory.Success(new WebAuthnAttestedCredential(
            credentialId,
            publicKey,
            algorithm,
            header.Value.SignatureCounter,
            authenticatorId,
            (flags & UserVerifiedFlag) != 0,
            (flags & BackedUpFlag) != 0));
    }

    public OperationResult<WebAuthnAssertionOutcome> VerifyAssertion(
        ReadOnlyMemory<byte> clientDataJson,
        ReadOnlyMemory<byte> authenticatorData,
        ReadOnlyMemory<byte> signature,
        WebAuthnAssertionExpectation expectation)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        if (signature.Length is 0 or > WebAuthnLimits.MaximumSignatureLength
            || authenticatorData.Length
                > WebAuthnLimits.MaximumAuthenticatorDataLength)
        {
            return Fail<WebAuthnAssertionOutcome>(
                WebAuthnErrors.SignatureInvalid());
        }

        var ceremony = new WebAuthnCeremonyExpectation(
            expectation.RelyingPartyId,
            expectation.Origins,
            expectation.Challenge,
            expectation.UserVerificationRequired);
        var clientData = ReadClientData(clientDataJson, GetCeremony, ceremony);
        if (!clientData.IsSuccess)
        {
            return OperationResultFactory.Fail<WebAuthnAssertionOutcome>(
                clientData.Errors);
        }

        var header = ReadAuthenticatorData(authenticatorData, ceremony);
        if (!header.IsSuccess)
        {
            return OperationResultFactory.Fail<WebAuthnAssertionOutcome>(
                header.Errors);
        }

        // The authenticator signs its own data followed by the hash of the
        // client's, which is what ties one signature to one challenge, one
        // origin and one relying party at once.
        var signed = new byte[authenticatorData.Length + SHA256.HashSizeInBytes];
        authenticatorData.Span.CopyTo(signed);
        SHA256.HashData(clientDataJson.Span, signed.AsSpan(authenticatorData.Length));
        if (!Verify(expectation, signed, signature.Span))
        {
            return Fail<WebAuthnAssertionOutcome>(WebAuthnErrors.SignatureInvalid());
        }

        var counter = header.Value.SignatureCounter;
        if (!CounterAdvanced(expectation.KnownSignatureCounter, counter))
        {
            // An authenticator that counts and then repeats itself has been
            // copied. One that never counts reports zero for ever, and there is
            // nothing to conclude from that.
            return Fail<WebAuthnAssertionOutcome>(WebAuthnErrors.CounterRegressed());
        }

        return OperationResultFactory.Success(new WebAuthnAssertionOutcome(
            counter,
            (header.Value.Flags & UserVerifiedFlag) != 0,
            (header.Value.Flags & BackedUpFlag) != 0));
    }

    private static bool CounterAdvanced(long? known, long reported)
        => known is null
            || (known.Value == 0 && reported == 0)
            || reported > known.Value;

    private static OperationResult ReadClientData(
        ReadOnlyMemory<byte> clientDataJson,
        string ceremony,
        WebAuthnCeremonyExpectation expectation)
    {
        if (clientDataJson.Length is 0
            or > WebAuthnLimits.MaximumClientDataLength)
        {
            return OperationResultFactory.Fail(WebAuthnErrors.ClientDataInvalid());
        }

        string? type;
        string? challenge;
        string? origin;
        try
        {
            using var document = JsonDocument.Parse(clientDataJson);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return OperationResultFactory.Fail(
                    WebAuthnErrors.ClientDataInvalid());
            }

            type = Text(root, "type");
            challenge = Text(root, "challenge");
            origin = Text(root, "origin");
        }
        catch (JsonException)
        {
            return OperationResultFactory.Fail(WebAuthnErrors.ClientDataInvalid());
        }

        if (type is null || challenge is null || origin is null)
        {
            return OperationResultFactory.Fail(WebAuthnErrors.ClientDataInvalid());
        }

        if (!string.Equals(type, ceremony, StringComparison.Ordinal))
        {
            // A registration response replayed into a sign-in, or the reverse.
            return OperationResultFactory.Fail(WebAuthnErrors.CeremonyMismatch());
        }

        if (!ChallengeMatches(challenge, expectation.Challenge.Span))
        {
            return OperationResultFactory.Fail(WebAuthnErrors.ChallengeMismatch());
        }

        // Exact, and against a list the server holds. This is the check that
        // makes a passkey useless on a look-alike page.
        if (!expectation.Origins.Contains(origin, StringComparer.Ordinal))
        {
            return OperationResultFactory.Fail(WebAuthnErrors.OriginNotAllowed());
        }

        return OperationResultFactory.Success();

        static string? Text(JsonElement root, string name)
            => root.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
    }

    private static bool ChallengeMatches(string encoded, ReadOnlySpan<byte> expected)
    {
        if (expected.Length is < WebAuthnLimits.MinimumChallengeLength
                or > WebAuthnLimits.MaximumChallengeLength
            || encoded.Length > WebAuthnLimits.MaximumChallengeLength * 2)
        {
            return false;
        }

        Span<byte> decoded = stackalloc byte[WebAuthnLimits.MaximumChallengeLength];
        return Base64Url.IsValid(encoded)
            && Base64Url.DecodeFromChars(encoded, decoded, out _, out var written)
                == OperationStatus.Done
            && CryptographicOperations.FixedTimeEquals(decoded[..written], expected);
    }

    private static OperationResult<AuthenticatorHeader> ReadAuthenticatorData(
        ReadOnlyMemory<byte> authenticatorData,
        WebAuthnCeremonyExpectation expectation)
    {
        if (authenticatorData.Length < HeaderLength)
        {
            return Fail<AuthenticatorHeader>(WebAuthnErrors.AttestationInvalid());
        }

        var span = authenticatorData.Span;
        Span<byte> expectedHash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(
            Encoding.UTF8.GetBytes(expectation.RelyingPartyId),
            expectedHash);
        if (!CryptographicOperations.FixedTimeEquals(
                span[..SHA256.HashSizeInBytes],
                expectedHash))
        {
            return Fail<AuthenticatorHeader>(WebAuthnErrors.RelyingPartyMismatch());
        }

        var flags = span[32];
        if ((flags & UserPresentFlag) == 0)
        {
            return Fail<AuthenticatorHeader>(WebAuthnErrors.UserNotPresent());
        }

        if (expectation.UserVerificationRequired && (flags & UserVerifiedFlag) == 0)
        {
            return Fail<AuthenticatorHeader>(WebAuthnErrors.UserNotVerified());
        }

        return OperationResultFactory.Success(new AuthenticatorHeader(
            flags,
            BinaryPrimitives.ReadUInt32BigEndian(span.Slice(33, 4))));
    }

    private static bool TryReadAttestation(
        ReadOnlyMemory<byte> attestationObject,
        out ReadOnlyMemory<byte> authenticatorData)
    {
        authenticatorData = default;
        try
        {
            var reader = new CborReader(attestationObject, CborConformanceMode.Strict);
            var entries = reader.ReadStartMap();
            if (entries is null)
            {
                return false;
            }

            byte[]? found = null;
            for (var entry = 0; entry < entries.Value; entry++)
            {
                var key = reader.ReadTextString();
                if (string.Equals(key, "authData", StringComparison.Ordinal))
                {
                    found = reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();
            if (found is null)
            {
                return false;
            }

            authenticatorData = found;
            return true;
        }
        catch (CborContentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// The part of the authenticator data that only a registration carries: the
    /// authenticator model, the identifier of the new credential, and the
    /// credential's public key in COSE form.
    /// </summary>
    private static bool TryReadAttestedCredential(
        ReadOnlyMemory<byte> authenticatorData,
        out Guid authenticatorId,
        out ReadOnlyMemory<byte> credentialId,
        out ReadOnlyMemory<byte> coseKey)
    {
        authenticatorId = Guid.Empty;
        credentialId = default;
        coseKey = default;
        var offset = HeaderLength;
        if (authenticatorData.Length < offset + AaGuidLength + CredentialIdPrefixLength)
        {
            return false;
        }

        var span = authenticatorData.Span;
        // Big-endian, which is not the layout Guid reads raw bytes in.
        authenticatorId = new Guid(span.Slice(offset, AaGuidLength), bigEndian: true);
        offset += AaGuidLength;
        var length = BinaryPrimitives.ReadUInt16BigEndian(
            span.Slice(offset, CredentialIdPrefixLength));
        offset += CredentialIdPrefixLength;
        if (length is < WebAuthnLimits.MinimumCredentialIdLength
                or > WebAuthnLimits.MaximumCredentialIdLength
            || authenticatorData.Length < offset + length)
        {
            return false;
        }

        credentialId = authenticatorData.Slice(offset, length);
        coseKey = authenticatorData[(offset + length)..];
        return coseKey.Length > 0;
    }

    private static bool TryReadPublicKey(
        ReadOnlyMemory<byte> coseKey,
        out WebAuthnAlgorithm algorithm,
        out ReadOnlyMemory<byte> publicKey)
    {
        algorithm = default;
        publicKey = default;
        try
        {
            // The key is followed by the extensions when there are any, and
            // CBOR says where each value ends, so the reader stops by itself.
            var reader = new CborReader(coseKey, CborConformanceMode.Strict);
            var entries = reader.ReadStartMap();
            if (entries is null)
            {
                return false;
            }

            long keyType = 0;
            long declared = 0;
            long curve = 0;
            byte[]? first = null;
            byte[]? second = null;
            for (var entry = 0; entry < entries.Value; entry++)
            {
                switch (reader.ReadInt64())
                {
                    case 1:
                        keyType = reader.ReadInt64();
                        break;
                    case 3:
                        declared = reader.ReadInt64();
                        break;
                    // An elliptic-curve key names its curve at -1 and carries
                    // its two coordinates at -2 and -3; an RSA key puts its
                    // modulus at -1 and its exponent at -2.
                    case -1 when keyType == KeyTypes.EllipticCurve:
                        curve = reader.ReadInt64();
                        break;
                    case -1:
                        first = reader.ReadByteString();
                        break;
                    case -2 when keyType == KeyTypes.EllipticCurve:
                        first = reader.ReadByteString();
                        break;
                    case -2:
                        second = reader.ReadByteString();
                        break;
                    case -3 when keyType == KeyTypes.EllipticCurve:
                        second = reader.ReadByteString();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }

            if (first is null || second is null)
            {
                return false;
            }

            // Kept as a SubjectPublicKeyInfo, so that everything after
            // registration works in the key format the platform reads on its
            // own and nothing else in this library has to know COSE.
            if (declared == (long)WebAuthnAlgorithm.Es256
                && keyType == KeyTypes.EllipticCurve
                && curve == Curves.P256
                && first.Length == 32
                && second.Length == 32)
            {
                using var key = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = first, Y = second },
                });
                algorithm = WebAuthnAlgorithm.Es256;
                publicKey = key.ExportSubjectPublicKeyInfo();
                return true;
            }

            if (declared == (long)WebAuthnAlgorithm.Rs256
                && keyType == KeyTypes.Rsa
                && first.Length is > 0 and <= 1024
                && second.Length is > 0 and <= 8)
            {
                using var key = RSA.Create(new RSAParameters
                {
                    Modulus = first,
                    Exponent = second,
                });
                algorithm = WebAuthnAlgorithm.Rs256;
                publicKey = key.ExportSubjectPublicKeyInfo();
                return true;
            }

            return false;
        }
        catch (CborContentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool Verify(
        WebAuthnAssertionExpectation expectation,
        ReadOnlySpan<byte> signed,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            switch (expectation.Algorithm)
            {
                case WebAuthnAlgorithm.Es256:
                    using (var key = ECDsa.Create())
                    {
                        key.ImportSubjectPublicKeyInfo(
                            expectation.PublicKey.Span,
                            out _);
                        // WebAuthn carries an elliptic-curve signature in the
                        // DER form, not as the raw pair .NET assumes.
                        return key.VerifyData(
                            signed,
                            signature,
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.Rfc3279DerSequence);
                    }

                case WebAuthnAlgorithm.Rs256:
                    using (var key = RSA.Create())
                    {
                        key.ImportSubjectPublicKeyInfo(
                            expectation.PublicKey.Span,
                            out _);
                        return key.VerifyData(
                            signed,
                            signature,
                            HashAlgorithmName.SHA256,
                            RSASignaturePadding.Pkcs1);
                    }

                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static OperationResult<T> Fail<T>(Error error)
        => OperationResultFactory.Fail<T>(error);

    private static class KeyTypes
    {
        public const long EllipticCurve = 2;
        public const long Rsa = 3;
    }

    private static class Curves
    {
        public const long P256 = 1;
    }

    private readonly record struct AuthenticatorHeader(
        byte Flags,
        long SignatureCounter);
}
