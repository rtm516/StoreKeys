using System.Text;

namespace StoreKeys.Licensing;

/// <summary>
/// The <c>clientChallenge</c> field of a licence request: 377 bytes of XML declaring three
/// protocol versions. Despite the service reporting a missing one as "DeviceEkbRequired", it is
/// not a device EKB and not device-bound - it is a constant, so we emit it rather than calling
/// into clipc.dll.
/// </summary>
internal static class ClientChallenge
{
    public const string Namespace = "http://schemas.microsoft.com/onestore/security/mkms/LicReq/v1";

    public const int DefaultChallengeVersion = 2;
    public const int DefaultLicenseProtocolVersion = 5;
    public const int DefaultSigningKeyVersion = 1;
    public const int DefaultClientVersion = 2;

    /// <summary>Builds the XML exactly as the OS emits it, then base64-encodes it.</summary>
    public static string Build(
        int challengeVersion = DefaultChallengeVersion,
        int licenseProtocolVersion = DefaultLicenseProtocolVersion,
        int signingKeyVersion = DefaultSigningKeyVersion,
        int clientVersion = DefaultClientVersion)
    {
        // Emitted as a literal rather than via XmlWriter: the service sees the bytes, and the
        // captured original has no whitespace, a space before "?>", and this exact attribute
        // order. Reproducing it verbatim removes any doubt about canonicalisation.
        var xml =
            "<?xml version=\"1.0\" encoding=\"utf-8\" ?>" +
            "<ClientChallenge " +
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
            "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
            $"xmlns=\"{Namespace}\" " +
            $"Version=\"{challengeVersion}\">" +
            $"<LicenseProtocolVersion>{licenseProtocolVersion}</LicenseProtocolVersion>" +
            $"<SigningKeyVersion>{signingKeyVersion}</SigningKeyVersion>" +
            $"<ClientVersion>{clientVersion}</ClientVersion>" +
            "</ClientChallenge>";

        return Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
    }
}
