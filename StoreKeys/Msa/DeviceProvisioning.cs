using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using CikExtractor.Models;
using StoreKeys.Internal;

namespace StoreKeys.Msa;

/// <summary>
/// Registers a device credential with MSA and returns the licence it issues.
/// </summary>
/// <remarks>
/// This is the alternative to reading the machine's own licence store: the device licence comes
/// back in the response, so no elevation and no registry are involved.
///
/// It creates state on Microsoft's identity service. The credential is a device registration,
/// not a user account, and carries no personal data beyond the hardware the challenge already
/// describes - but it is a write, so callers should do it once and cache the result.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class DeviceProvisioning
{
    private const string Endpoint = "https://login.live.com/ppsecure/deviceaddcredential.srf";

    private const string UserAgent = "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; "
                                   + "IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)";

    /// <summary>Component ids the request carries.</summary>
    private const int ComponentUnknown4113 = 4113;

    private const int ComponentSmbiosVersion = 4100;
    private const int ComponentSmbiosSerial = 4101;
    private const int ComponentSmbiosUuid = 4102;
    private const int ComponentClepV2 = 8196;
    private const int ComponentClepV4 = 8197;
    private const int ComponentUnknown4145 = 4145;
    private const int ComponentUnknown4160 = 4160;
    private const int ComponentUnknown4161 = 4161;

    /// <summary>Error the OS reports for a component it cannot produce.</summary>
    private const string ComponentError = "-2147024894";

    public readonly record struct Result(
        string Membername,
        string Password,
        string DeviceLicense,
        byte[] EncryptedDeviceKey);

    /// <summary>
    /// Provisions a new device and returns its credential plus the EncryptedDeviceKey block of
    /// the licence it was issued.
    /// </summary>
    public static async Task<Result> ProvisionAsync(
        HttpClient http,
        CancellationToken cancellationToken = default)
    {
        var membername = "02" + RandomText(14);
        var password = RandomText(20);

        var (challengeV2, challengeV4) = ClepChallenge.Build(Hardware.Smbios(), Hardware.DriveSerial());
        var body = BuildRequest(membername, password, challengeV2, challengeV4);

        using var message = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/soap+xml"),
        };
        message.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var response = await http.SendAsync(message, cancellationToken);
        var text = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
            throw new StoreKeysException(
                $"Device provisioning failed: HTTP {(int)response.StatusCode}. {Summarise(text)}");

        var document = Parse(text);

        var licence = document.Descendants()
                          .FirstOrDefault(e => e.Name.LocalName == "SPLicenseBlock")?.Value.Trim()
                      ?? throw new StoreKeysException(
                          $"Device provisioning returned no licence. {Summarise(text)}");

        var encryptedDeviceKey = new SpLicense(Convert.FromBase64String(licence)).EncryptedDeviceKey
                                 ?? throw new StoreKeysException(
                                     "The provisioned licence carries no EncryptedDeviceKey block.");

        return new Result(membername, password, licence, encryptedDeviceKey);
    }

    private static string BuildRequest(
        string membername,
        string password,
        byte[] challengeV2,
        byte[] challengeV4)
    {
        static XElement Value(int id, string value) =>
            new("Component", new XAttribute("name", id), value);

        static XElement Error(int id) =>
            new("Component", new XAttribute("name", id), new XAttribute("error", ComponentError));

        // The SMBIOS components are reported as errors: the CLEP challenges already carry that
        // data, and this is the combination provisioning is known to work with.
        var components = new[]
        {
            Value(ComponentUnknown4113, "AA=="),
            Error(ComponentSmbiosVersion),
            Error(ComponentSmbiosSerial),
            Error(ComponentSmbiosUuid),
            Value(ComponentClepV2, Convert.ToBase64String(challengeV2)),
            Value(ComponentClepV4, Convert.ToBase64String(challengeV4)),
            Value(ComponentUnknown4145, "AQAAAA=="),
            Error(ComponentUnknown4160),
            Error(ComponentUnknown4161),
        };

        var document = new XElement("DeviceAddRequest",
            new XElement("ClientInfo",
                new XAttribute("name", "IDCRL"),
                new XAttribute("version", "1.0"),
                new XElement("BinaryVersion", 55)),
            new XElement("Authentication",
                new XElement("Membername", membername),
                new XElement("Password", password)),
            new XElement("DeviceInfo",
                new XAttribute("Id", "DeviceInfo"),
                components));

        return "<?xml version=\"1.0\"?>\n" + document.ToString(SaveOptions.DisableFormatting);
    }

    private static XDocument Parse(string text)
    {
        try
        {
            return XDocument.Parse(text);
        }
        catch (Exception ex)
        {
            throw new StoreKeysException(
                $"Device provisioning returned a response that is not XML: {ex.Message}");
        }
    }

    /// <summary>Whatever fault the service reported, without echoing the whole body.</summary>
    private static string Summarise(string text)
    {
        try
        {
            var fault = XDocument.Parse(text).Descendants()
                .FirstOrDefault(e => e.Name.LocalName is "Fault" or "Error" or "ErrorCode");

            if (fault is not null)
                return string.Join(' ', fault.ToString().Split('\n').Select(l => l.Trim()));
        }
        catch
        {
            // fall through to the truncated body
        }

        return text.Length <= 300 ? text : text[..300] + "...";
    }

    private static string RandomText(int length)
    {
        const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        var builder = new StringBuilder(length);
        for (var i = 0; i < length; i++)
            builder.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);

        return builder.ToString();
    }
}
