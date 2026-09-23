using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using CikExtractor.Models;
using StoreKeys.Internal;

namespace StoreKeys.Msa;

/// <summary>
/// Obtains a licensing device token for a provisioned credential, by signing a WS-Trust request
/// with the RSA key inside the credential's own device licence.
/// </summary>
/// <remarks>
/// The licensing service wants a device ticket in its Authorization header, and a provisioned
/// identity has to mint its own: the service wraps a CIK under the key of whichever device
/// authenticated, so a provisioned key is only usable with a provisioned token.
///
/// The envelope matches signed RST2.srf requests captured from the OS, and three details there
/// are load-bearing. The timestamp is addressed by <c>wsu:Id</c> where everything else uses a
/// plain <c>Id</c>. Both scopes are requested together in one envelope. And a service scope is
/// written in query-string form, not as the bare <c>service::…</c> string WAM accepts.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class DeviceAuthentication
{
    private const string Endpoint = "https://login.live.com/RST2.srf";

    private const string UserAgent = "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; "
                                   + "IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)";

    /// <summary>Device relying party. Asked for alongside the real scope, as the OS does.</summary>
    private const string DeviceScope = "http://Passport.NET/tb";

    /// <summary>
    /// Licensing relying party. RST2.srf wants a service scope in query-string form with the
    /// requesting client id; the bare <c>service::…</c> string is refused with 0x80045c31.
    /// </summary>
    private static string LicensingScope =>
        "scope=service::licensing.mp.microsoft.com::MBI_SSL"
        + $"&uaid={Guid.NewGuid():N}"
        + "&clientid=268761a2-03f3-40df-8a8b-c3db24145b6b";

    private static readonly XNamespace S = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace Ps = "http://schemas.microsoft.com/Passport/SoapServices/PPCRL";
    private static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static readonly XNamespace Wsa = "http://www.w3.org/2005/08/addressing";
    private static readonly XNamespace Wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    private static readonly XNamespace Wst = "http://schemas.xmlsoap.org/ws/2005/02/trust";

    private const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>
    /// Authenticates the device and returns the token for the licensing Authorization header.
    /// </summary>
    public static async Task<string> GetLicensingTokenAsync(
        HttpClient http,
        string membername,
        string password,
        string deviceLicense,
        CancellationToken cancellationToken = default)
    {
        var licence = new SpLicense(Convert.FromBase64String(deviceLicense));

        if (licence.ClepSignState is not { } signState)
            throw new StoreKeysException("The device licence carries no ClepSignState to sign with.");

        using var rsa = ClepSecrets.RsaSigningKey(signState);

        var signed = Sign(BuildEnvelope(membername, password, [LicensingScope, DeviceScope]), rsa);

        using var message = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Content = new StringContent(signed, Encoding.UTF8, "application/soap+xml"),
        };
        message.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var response = await http.SendAsync(message, cancellationToken);
        var text = await response.Content.ReadAsStringAsync(cancellationToken);

        return ExtractToken(text, response.StatusCode);
    }

    /// <summary>The unsigned envelope. The Ids here are what the signature references.</summary>
    private static XDocument BuildEnvelope(
        string membername,
        string password,
        IReadOnlyList<string> scopes)
    {
        var now = DateTimeOffset.UtcNow;

        string Stamp(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

        return new XDocument(
            new XElement(S + "Envelope",
                new XAttribute(XNamespace.Xmlns + "s", S),
                new XAttribute(XNamespace.Xmlns + "ps", Ps),
                new XAttribute(XNamespace.Xmlns + "wsse", Wsse),
                new XAttribute(XNamespace.Xmlns + "wsu", Wsu),
                new XAttribute(XNamespace.Xmlns + "wsa", Wsa),
                new XAttribute(XNamespace.Xmlns + "wsp", Wsp),
                new XAttribute(XNamespace.Xmlns + "wst", Wst),

                new XElement(S + "Header",
                    new XElement(Wsa + "Action",
                        new XAttribute(S + "mustUnderstand", "1"),
                        "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"),
                    new XElement(Wsa + "To",
                        new XAttribute(S + "mustUnderstand", "1"),
                        "https://login.live.com:443/RST2.srf"),
                    new XElement(Wsa + "MessageID", now.ToUnixTimeSeconds().ToString()),

                    new XElement(Ps + "AuthInfo",
                        new XAttribute("Id", "PPAuthInfo"),
                        new XElement(Ps + "SSOFlags", ""),
                        new XElement(Ps + "HostingApp", "{DF60E2DF-88AD-4526-AE21-83D130EF0F68}"),
                        new XElement(Ps + "BinaryVersion", "55"),
                        new XElement(Ps + "UIVersion", "1"),
                        new XElement(Ps + "InlineUX", "TokenBroker"),
                        new XElement(Ps + "IsAdmin", "1"),
                        new XElement(Ps + "Cookies", ""),
                        new XElement(Ps + "RequestParams", "AQAAAAIAAABsYwQAAAAxMDMz"),
                        new XElement(Ps + "WindowsClientString", "b4d/QB7Zy5pjUAY9ByQ1echTyTITx6ZCErOEztuIVtw="),
                        new XElement(Ps + "LicenseSignatureKeyVersion", "2"),
                        new XElement(Ps + "ClientCapabilities", "1")),

                    new XElement(Wsse + "Security",
                        new XElement(Wsse + "UsernameToken",
                            // wsu:Id, not Id: with a plain Id the service cannot read the member
                            // name and answers 0x80041034.
                            new XAttribute(Wsu + "Id", "devicesoftware"),
                            new XElement(Wsse + "Username", membername),
                            new XElement(Wsse + "Password", password)),
                        new XElement(Wsu + "Timestamp",
                            new XAttribute(Wsu + "Id", "Timestamp"),
                            new XElement(Wsu + "Created", Stamp(now)),
                            new XElement(Wsu + "Expires", Stamp(now.AddMinutes(5)))))),

                new XElement(S + "Body", RequestedTokens(scopes))));
    }

    /// <summary>
    /// One token request per scope. Several are wrapped in a single element, which is what the
    /// signature then covers as a whole.
    /// </summary>
    private static XElement RequestedTokens(IReadOnlyList<string> scopes)
    {
        var requests = scopes.Select((scope, index) =>
            new XElement(Wst + "RequestSecurityToken",
                new XAttribute("Id", $"RST{index}"),
                new XElement(Wst + "RequestType",
                    "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"),
                new XElement(Wsp + "AppliesTo",
                    new XElement(Wsa + "EndpointReference",
                        new XElement(Wsa + "Address", scope))),
                // Only the service scope carries a policy; the device scope goes bare.
                scope == DeviceScope
                    ? null
                    : new XElement(Wsp + "PolicyReference", new XAttribute("URI", "TOKEN_BROKER"))));

        return scopes.Count == 1
            ? requests.Single()
            : new XElement(Ps + "RequestMultipleSecurityTokens",
                new XAttribute(XNamespace.Xmlns + "ps", Ps),
                new XAttribute("Id", "RSTS"),
                requests);
    }

    /// <summary>
    /// Signs AuthInfo, the timestamp and the token request, and puts the signature in the
    /// security header.
    /// </summary>
    private static string Sign(XDocument envelope, RSA rsa)
    {
        // Whitespace is part of what gets digested, so the document must not be reformatted
        // between signing and sending.
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(envelope.ToString(SaveOptions.DisableFormatting));

        var signer = new WsSecuritySignedXml(document)
        {
            SigningKey = rsa,
        };

        signer.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signer.SignedInfo.SignatureMethod = RsaSha256;

        // Multi-scope requests sign the wrapper; a single request is signed directly.
        var tokens = document.GetElementsByTagName("RequestMultipleSecurityTokens", Ps.NamespaceName).Count > 0
            ? "#RSTS"
            : "#RST0";

        foreach (var id in new[] { tokens, "#Timestamp", "#PPAuthInfo" })
        {
            var reference = new Reference(id) { DigestMethod = Sha256 };
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signer.AddReference(reference);
        }

        signer.ComputeSignature();

        var security = document.GetElementsByTagName("Security", Wsse.NamespaceName)[0]
                       ?? throw new StoreKeysException("Security header went missing while signing.");
        security.AppendChild(document.ImportNode(signer.GetXml(), deep: true));

        return document.OuterXml;
    }

    /// <summary>
    /// The compact token for the service scope. The device scope's token comes back encrypted
    /// alongside it and is not needed here.
    /// </summary>
    private static string ExtractToken(string responseText, System.Net.HttpStatusCode status)
    {
        XDocument document;
        try
        {
            document = XDocument.Parse(responseText);
        }
        catch (Exception ex)
        {
            throw new StoreKeysException($"Device authentication returned non-XML: {ex.Message}");
        }

        var token = document.Descendants()
            .FirstOrDefault(e => e.Name.LocalName == "BinarySecurityToken")?.Value.Trim();

        if (!string.IsNullOrEmpty(token))
            return token.StartsWith("t=", StringComparison.Ordinal) ? token[2..] : token;

        // A per-scope refusal is reported as errorstatus; a whole-request failure as a fault.
        var problem = document.Descendants()
            .FirstOrDefault(e => e.Name.LocalName is "errorstatus" or "internalerror" or "Fault");

        throw new StoreKeysException(
            $"Device authentication did not return a token (HTTP {(int)status}). "
            + (problem is null
                ? $"Response elements: {string.Join(", ", document.Descendants().Select(e => e.Name.LocalName).Distinct())}"
                : $"{string.Join(' ', problem.ToString().Split('\n').Select(l => l.Trim()))}"));
    }

    /// <summary>
    /// SignedXml only resolves plain <c>Id</c> attributes. WS-Security addresses the timestamp
    /// by <c>wsu:Id</c>, so without this that reference silently fails to bind.
    /// </summary>
    private sealed class WsSecuritySignedXml(XmlDocument document) : SignedXml(document)
    {
        private readonly XmlDocument _document = document;

        public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
        {
            if (base.GetIdElement(document, idValue) is { } found)
                return found;

            var target = document ?? _document;
            var namespaces = new XmlNamespaceManager(target.NameTable);
            namespaces.AddNamespace("wsu", Wsu.NamespaceName);

            return target.SelectSingleNode($"//*[@wsu:Id='{idValue}']", namespaces) as XmlElement;
        }
    }
}
