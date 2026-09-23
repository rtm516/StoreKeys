using StoreKeys.Catalog;
using StoreKeys.Internal;
using StoreKeys.Licensing;

namespace StoreKeys;

/// <summary>
/// A piece of Microsoft Store content, resolved from whatever identifier you have, and the
/// entry point for fetching its content keys.
/// </summary>
/// <example>
/// <code>
/// var content = await StoreContent.FromUrlAsync("https://www.xbox.com/en-GB/games/store/minecraft-for-windows/9nblggh2jhxj");
/// var keys    = await content.FetchCikAsync(deviceKey);
///
/// Guid id = StoreContent.FromFile("Minecraft....msixvc").ContentId;
/// </code>
/// </example>
/// <remarks>
/// Nothing here reads or writes files other than an XVC you explicitly point it at. The sync
/// factories resolve without I/O; the async ones ask DisplayCatalog or range-read a header.
/// </remarks>
public sealed class StoreContent
{
    private StoreContent(
        IReadOnlyList<Guid> contentIds,
        string? packageFamilyName = null,
        string? productId = null,
        string? title = null,
        IReadOnlyList<string>? platforms = null)
    {
        ContentIds = contentIds;
        PackageFamilyName = packageFamilyName;
        ProductId = productId;
        Title = title;
        Platforms = platforms ?? [];
    }

    /// <summary>Every ContentId this identifier maps to; a product can ship several packages.</summary>
    public IReadOnlyList<Guid> ContentIds { get; }

    /// <summary>The first ContentId, which is the one a single-package title has.</summary>
    public Guid ContentId => ContentIds[0];

    /// <summary>Package family name, when resolved through the catalog. Null otherwise.</summary>
    public string? PackageFamilyName { get; }

    /// <summary>Store product id, when resolved from one. Null otherwise.</summary>
    public string? ProductId { get; }

    /// <summary>Display title, when the catalog supplied one.</summary>
    public string? Title { get; }

    /// <summary>Platform per package, e.g. "Windows.Desktop", "Windows.Xbox".</summary>
    public IReadOnlyList<string> Platforms { get; }

    /// <summary>
    /// True when every package targets an Xbox console. Such titles cannot be reached from a
    /// PC: there is no PC package to license, and the licensing service refuses a PC identity
    /// for console content. Their keys are also wrapped under the ODK rather than a device key.
    /// </summary>
    public bool IsXboxOnly =>
        Platforms.Count > 0
        && Platforms.All(p => p.Contains("Xbox", StringComparison.OrdinalIgnoreCase));

    // ------------------------------------------------------------- factories

    /// <summary>A ContentId you already know.</summary>
    public static StoreContent FromContentId(Guid contentId) => new([contentId]);

    /// <summary>
    /// A local XVC/XVD file. Reads the VDUID at offset 0x220 of the header, which is the
    /// ContentId the licensing service expects - not a Store product id.
    /// </summary>
    public static StoreContent FromFile(string path)
        => new([XvcHeader.ReadFromFile(path).ContentId]);

    /// <summary>A Store product id, e.g. "9nblggh2jhxj". Queries DisplayCatalog.</summary>
    public static async Task<StoreContent> FromProductIdAsync(
        string productId,
        CancellationToken cancellationToken = default)
    {
        var result = await StoreCatalog.ResolveAsync(productId, cancellationToken);

        return new StoreContent(
            result.ContentIds,
            result.PackageFamilyName,
            result.ProductId,
            result.Title,
            result.Platforms);
    }

    /// <summary>
    /// A store page URL (xbox.com or microsoft.com), or a direct URL to an XVC. Store URLs go
    /// through the catalog; anything else is range-read for its header, so no download happens.
    /// </summary>
    public static async Task<StoreContent> FromUrlAsync(
        string url,
        CancellationToken cancellationToken = default)
    {
        if (StoreCatalog.TryExtractProductId(url) is { } productId)
            return await FromProductIdAsync(productId, cancellationToken);

        var header = await XvcHeader.ReadFromUrlAsync(url, cancellationToken);
        return new StoreContent([header.ContentId]);
    }

    /// <summary>
    /// Resolves whatever you have: a ContentId GUID, an existing file path, a Store product id
    /// or page URL, or a URL to an XVC - in that order.
    /// </summary>
    public static async Task<StoreContent> FromAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        if (Guid.TryParse(identifier, out var contentId))
            return FromContentId(contentId);

        if (File.Exists(identifier))
            return FromFile(identifier);

        if (StoreCatalog.TryExtractProductId(identifier) is { } productId)
            return await FromProductIdAsync(productId, cancellationToken);

        return await FromUrlAsync(identifier, cancellationToken);
    }

    // ------------------------------------------------------------------ keys

    /// <summary>
    /// Asks the Store licensing service for this content's keys and unwraps them with the
    /// credential's device key.
    /// </summary>
    /// <param name="credential">
    /// The device identity to fetch as. Its key and its device token have to belong to the same
    /// device, which is why this takes a credential rather than a bare key.
    /// </param>
    /// <param name="cancellationToken">Cancels the licence requests.</param>
    /// <remarks>
    /// Every ContentId is tried: a product can ship several packages, and a failure on one - a
    /// console SKU, typically - says nothing about the others.
    /// </remarks>
    public async Task<IReadOnlyList<ContentKey>> FetchCikAsync(
        DeviceCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        if (!credential.IsProvisioned)
            return await FetchCikAsync(credential.DeviceKey, cancellationToken);

        if (!OperatingSystem.IsWindows())
            throw new StoreKeysException("Device authentication needs Windows.");

        // A provisioned identity mints its own token: the service wraps the CIK under the key of
        // whichever device authenticated, so this token and this key have to be the same device.
        using var http = new HttpClient();
        var deviceToken = await Msa.DeviceAuthentication.GetLicensingTokenAsync(
            http, credential.Membername!, credential.Password!, credential.DeviceLicense!, cancellationToken);

        return await FetchCikAsync(credential.DeviceKey, deviceToken, cancellationToken);
    }

    /// <inheritdoc cref="FetchCikAsync(DeviceCredential, CancellationToken)"/>
    public Task<IReadOnlyList<ContentKey>> FetchCikAsync(
        byte[] deviceKey,
        CancellationToken cancellationToken = default)
        => FetchCikAsync(deviceKey, deviceToken: null, cancellationToken);

    private async Task<IReadOnlyList<ContentKey>> FetchCikAsync(
        byte[] deviceKey,
        string? deviceToken,
        CancellationToken cancellationToken)
    {
        var keys = new List<ContentKey>();
        var failures = new List<string>();

        foreach (var contentId in ContentIds)
        {
            var response = await LicenseService.RequestAsync(contentId, cancellationToken, deviceToken);

            if (!response.IsSuccess || response.SatisfactionFailure is not null)
            {
                failures.Add($"{contentId}: {response.Describe()}");
                continue;
            }

            keys.AddRange(CikUnwrap.FromLicenseResponse(response.Json, deviceKey));
        }

        if (keys.Count == 0)
            throw new StoreKeysException(
                "The licensing service returned no keys for this content."
                + (failures.Count == 0 ? "" : " " + string.Join("; ", failures)));

        return keys;
    }

    // -------------------------------------------------------------- packages

    /// <summary>
    /// The downloadable package files for this content, with CDN URLs, via Windows Update's
    /// FE3 service. Only available for content resolved from a Store product id.
    /// </summary>
    /// <remarks>
    /// Paid titles list nothing without a Windows Update ticket - an anonymous query returns
    /// update metadata but strips every file entry - so one is fetched automatically here.
    /// </remarks>
    public async Task<IReadOnlyList<StorePackage>> FetchPackagesAsync(
        CancellationToken cancellationToken = default)
    {
        if (ProductId is null)
            throw new StoreKeysException(
                "Packages can only be listed for content resolved from a Store product id.");

        return await StoreCatalog.GetDownloadablePackagesAsync(ProductId, cancellationToken);
    }
}

/// <summary>A downloadable package file and where to get it.</summary>
public sealed record StorePackage(string Identifier, Uri? DownloadUrl, string PackageType);
