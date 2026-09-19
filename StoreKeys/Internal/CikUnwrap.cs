using System.Text.Json.Nodes;
using System.Xml.Linq;
using CikExtractor;
using LibXboxOne;

namespace StoreKeys.Internal;

/// <summary>
/// Turns a licence - whether a JSON response from the licensing service or a licence XML file -
/// into unwrapped content keys.
/// </summary>
/// <remarks>
/// CIKs sit in an SPLicenseBlock's PackedContentKeys block, wrapped with RFC 3394 AES Key Wrap
/// under the device key. Block parsing is LibXboxOne's; the unwrap is CikExtractor's.
/// </remarks>
internal static class CikUnwrap
{
    private const string StoreLicenseNs = "urn:schemas-microsoft-com:windows:store:licensing:ls";
    private const string XboxLicenseNs = "http://schemas.microsoft.com/xboxlive/security/clas/LicResp/v1";

    /// <summary>Keys from a licensing-service JSON response.</summary>
    public static IReadOnlyList<ContentKey> FromLicenseResponse(JsonNode? response, byte[] deviceKey)
        => FindLicenseBlocks(response)
            .SelectMany(block => FromLicenseBlock(Convert.FromBase64String(block), deviceKey))
            .ToList();

    /// <summary>Keys from a licence XML document.</summary>
    public static IReadOnlyList<ContentKey> FromLicenseXml(string xml, byte[] deviceKey)
        => BlocksFromXml(xml)
            .SelectMany(block => FromLicenseBlock(Convert.FromBase64String(block), deviceKey))
            .ToList();

    /// <summary>Keys from a raw SPLicenseBlock.</summary>
    public static IReadOnlyList<ContentKey> FromLicenseBlock(byte[] licenseBlock, byte[] deviceKey)
    {
        if (deviceKey.Length != DeviceKey.Size)
            throw new ArgumentException(
                $"A device key is {DeviceKey.Size} bytes, got {deviceKey.Length}.", nameof(deviceKey));

        XvcLicenseBlock? packed;
        try
        {
            packed = new XvcLicenseBlock(licenseBlock).GetBlockWithId(XvcLicenseBlockId.PackedContentKeys);
        }
        catch (NullReferenceException)
        {
            // LibXboxOne's block walker dereferences NextBlockData without a null check when a
            // block ends exactly on the buffer boundary. Real responses hit this: a licence
            // carries both a key block and a lease block, and the lease has no content keys.
            return [];
        }

        if (packed?.BlockData is not { Length: > 0 } data)
            return [];

        var keys = new List<ContentKey>();

        using var reader = new BinaryReader(new MemoryStream(data));
        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var keyIdSize = reader.ReadUInt16();   // 0x20: two GUIDs
            var keyEntrySize = reader.ReadUInt16(); // 0x28: 32-byte key + 8-byte KW integrity

            if (keyIdSize != 0x20 || keyEntrySize != 0x28)
                throw new StoreKeysException(
                    $"Unexpected packed key sizes (idSize=0x{keyIdSize:X}, entrySize=0x{keyEntrySize:X}).");

            var first = new Guid(reader.ReadBytes(0x10));
            var second = new Guid(reader.ReadBytes(0x10));
            var wrapped = reader.ReadBytes(keyEntrySize);

            // Both ids address the same key and an XVC header may reference either.
            IReadOnlyList<Guid> ids = first == second ? [first] : [first, second];

            keys.Add(new ContentKey(ids, Crypto.DecryptContentKey(deviceKey, wrapped)));
        }

        return keys;
    }

    /// <summary>Every base64 SPLicenseBlock in a licensing-service response.</summary>
    private static IEnumerable<string> FindLicenseBlocks(JsonNode? json)
    {
        if (json is null) yield break;

        foreach (var value in Walk(json))
        foreach (var block in BlocksFromCandidate(value))
            yield return block;
    }

    private static IEnumerable<string> Walk(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, child) in obj)
                {
                    if (child is null) continue;

                    // Responses put the blob under keys[].value / signedLicense.
                    if (child is JsonValue v && name is "value" or "signedLicense" or "SPLicenseBlock"
                        && v.TryGetValue<string>(out var s))
                        yield return s;
                    else
                        foreach (var r in Walk(child)) yield return r;
                }
                break;

            case JsonArray arr:
                foreach (var child in arr)
                {
                    if (child is null) continue;
                    foreach (var r in Walk(child)) yield return r;
                }
                break;
        }
    }

    private static IEnumerable<string> BlocksFromCandidate(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) yield break;

        byte[] decoded;
        try { decoded = Convert.FromBase64String(candidate); }
        catch (FormatException) { yield break; }

        // If it decodes to XML it is a signed-licence wrapper; recurse into it.
        var text = System.Text.Encoding.UTF8.GetString(decoded);
        if (text.TrimStart().StartsWith('<'))
        {
            foreach (var inner in BlocksFromXml(text))
                yield return inner;

            yield break;
        }

        yield return candidate;
    }

    private static IEnumerable<string> BlocksFromXml(string xml)
    {
        XDocument document;
        try { document = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { yield break; }

        foreach (var ns in new[] { StoreLicenseNs, XboxLicenseNs })
        foreach (var element in document.Descendants(XName.Get("SPLicenseBlock", ns)))
            yield return element.Value;

        // Xbox CLAS responses nest the real document inside <SignedLicense> as base64.
        foreach (var signed in document.Descendants(XName.Get("SignedLicense", XboxLicenseNs)))
        {
            byte[] decoded;
            try { decoded = Convert.FromBase64String(signed.Value); }
            catch (FormatException) { continue; }

            foreach (var inner in BlocksFromXml(System.Text.Encoding.UTF8.GetString(decoded)))
                yield return inner;
        }
    }
}
