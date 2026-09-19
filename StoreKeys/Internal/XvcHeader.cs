using System.Net.Http.Headers;

namespace StoreKeys.Internal;

/// <summary>
/// Minimal reader for the parts of the XVD/XVC header we need to drive a license request.
///
/// The ContentId that <c>licensing.mp.microsoft.com</c> expects is the XVD header's VDUID
/// ("Drive Id") at offset 0x220. Verified against Minecraft Bedrock: the retail .msixvc carries
/// 7792d9ce-355a-493c-afbd-768f4a77c3b0, which matches the published Bedrock content id.
/// </summary>
internal static class XvcHeader
{
    private const int HeaderReadSize = 0x1000;
    private const int MagicOffset = 0x200;
    private const int VduidOffset = 0x220;
    private const int UduidOffset = 0x230;

    private static readonly byte[] XvdMagic = "msft-xvd"u8.ToArray();

    public readonly record struct XvcIdentity(Guid ContentId, Guid UserDataId);

    public static async Task<XvcIdentity> ReadAsync(string pathOrUrl, CancellationToken ct = default)
    {
        var header = Uri.TryCreate(pathOrUrl, UriKind.Absolute, out var uri)
                     && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? await ReadRemoteHeaderAsync(uri, ct)
            : await ReadLocalHeaderAsync(pathOrUrl, ct);

        return Parse(header);
    }

    public static XvcIdentity Parse(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderReadSize)
            throw new InvalidDataException($"Header is only 0x{header.Length:X} bytes, need 0x{HeaderReadSize:X}.");

        if (!header.Slice(MagicOffset, XvdMagic.Length).SequenceEqual(XvdMagic))
            throw new InvalidDataException("Not an XVD/XVC file: 'msft-xvd' magic missing at 0x200.");

        return new XvcIdentity(
            new Guid(header.Slice(VduidOffset, 16)),
            new Guid(header.Slice(UduidOffset, 16)));
    }

    /// <summary>Reads the header of a local XVC/XVD file.</summary>
    public static XvcIdentity ReadFromFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        var buffer = new byte[HeaderReadSize];
        fs.ReadExactly(buffer);

        return Parse(buffer);
    }

    /// <summary>Range-reads the header of a remote XVC/XVD, so nothing large is downloaded.</summary>
    public static async Task<XvcIdentity> ReadFromUrlAsync(string url, CancellationToken ct = default)
        => Parse(await ReadRemoteHeaderAsync(new Uri(url), ct));

    private static async Task<byte[]> ReadLocalHeaderAsync(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[HeaderReadSize];
        await fs.ReadExactlyAsync(buffer, ct);
        return buffer;
    }

    private static async Task<byte[]> ReadRemoteHeaderAsync(Uri uri, CancellationToken ct)
    {
        using var http = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Range = new RangeHeaderValue(0, HeaderReadSize - 1);

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsByteArrayAsync(ct);
    }
}
