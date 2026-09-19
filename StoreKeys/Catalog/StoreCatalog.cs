using System.Text.RegularExpressions;
using StoreLib.Models;
using StoreLib.Services;

namespace StoreKeys.Catalog;

/// <summary>
/// Resolves a Store product to the identifiers the rest of the tool needs, and to downloadable
/// packages, on top of <see href="https://github.com/StoreDev/StoreLib">StoreLib</see>. Kept
/// locally is only what StoreLib does not do: turning a pasted store URL into a product id.
/// </summary>
internal static class StoreCatalog
{
    /// <summary>Store ids are 12 characters of base-36-ish text, e.g. "9nblggh2jhxj".</summary>
    private static readonly Regex StoreIdPattern = new("^[A-Za-z0-9]{12}$", RegexOptions.Compiled);

    public readonly record struct CatalogPackage(Guid ContentId, string? PackageFamilyName, string? Platform);

    /// <summary>Everything a product id resolves to.</summary>
    public sealed record Resolution(
        string ProductId,
        string? Title,
        IReadOnlyList<Guid> ContentIds,
        string? PackageFamilyName,
        IReadOnlyList<string> Platforms);

    /// <summary>Resolves a product id to its packages, or throws if the catalog has nothing.</summary>
    public static async Task<Resolution> ResolveAsync(string productId, CancellationToken ct = default)
    {
        var handler = await QueryAsync(productId);
        var product = handler.ProductListing.Product;
        var packages = await GetPackagesAsync(productId);

        if (packages.Count == 0)
            throw new StoreKeysException(
                $"DisplayCatalog returned no packages for {productId}. "
                + "Console-only titles sometimes expose none on a PC market.");

        return new Resolution(
            productId,
            product.LocalizedProperties?.FirstOrDefault()?.ProductTitle,
            packages.Select(p => p.ContentId).ToList(),
            packages.Select(p => p.PackageFamilyName).FirstOrDefault(n => n is not null),
            packages.Select(p => p.Platform ?? "").Where(x => x.Length > 0).ToList());
    }

    /// <summary>
    /// Pulls a Store product id out of whatever the user pasted: a bare id, an xbox.com store
    /// URL, or a microsoft.com/store/productId URL. Null when it is neither.
    /// </summary>
    public static string? TryExtractProductId(string input)
    {
        input = input.Trim();

        if (StoreIdPattern.IsMatch(input))
            return input.ToUpperInvariant();

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri))
            return null;

        if (!uri.Host.EndsWith("xbox.com", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.EndsWith("microsoft.com", StringComparison.OrdinalIgnoreCase))
            return null;

        // The id is the last path segment on xbox.com/.../store/<slug>/<id>, and also the last
        // segment on microsoft.com/store/productId/<slug>/<id>.
        return uri.AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault(StoreIdPattern.IsMatch)
            ?.ToUpperInvariant();
    }

    /// <summary>Queries DisplayCatalog, throwing with a useful message when the id is unknown.</summary>
    public static async Task<DisplayCatalogHandler> QueryAsync(string productId)
    {
        // Market matters: a title can be listed in one region and not another, so follow the
        // machine's region rather than defaulting to US.
        var handler = new DisplayCatalogHandler(
            DCatEndpoint.Production,
            new Locale(CurrentMarket(), Lang.en, IncludeNeutral: true));

        await handler.QueryDCATAsync(productId);

        if (!handler.IsFound || handler.ProductListing?.Product is null)
            throw new InvalidOperationException(
                $"DisplayCatalog did not return {productId} ({handler.Result}). "
                + "Check the id, or the title may not be listed in this market.");

        return handler;
    }

    /// <summary>The machine's region as a StoreLib market, falling back to US.</summary>
    private static Market CurrentMarket()
    {
        try
        {
            var region = System.Globalization.RegionInfo.CurrentRegion.TwoLetterISORegionName;
            return Enum.TryParse<Market>(region, ignoreCase: true, out var market) ? market : Market.US;
        }
        catch
        {
            return Market.US;
        }
    }

    /// <summary>
    /// Downloadable package files with CDN URLs, resolved through Windows Update (FE3). Without
    /// a ticket FE3 answers but strips every SecuredFragment and file entry for paid content.
    /// </summary>
    public static async Task<IReadOnlyList<StorePackage>> GetDownloadablePackagesAsync(
        string productId,
        CancellationToken ct = default)
    {
        var handler = await QueryAsync(productId);

        string? wuTicket = null;
        try
        {
            wuTicket = await Msa.WamAuth.GetTokenAsync(WuTicketClientId, WuTicketScope);
        }
        catch (Exception)
        {
            // Free content still lists without one.
        }

        var packages = await handler.GetPackagesForProductAsync(wuTicket);

        return packages
            .Select(p => new StorePackage(
                p.PackageMoniker ?? "(unknown)",
                p.PackageUri,
                p.PackageType.ToString()))
            .ToList();
    }

    /// <summary>Client id and scope WUTokenHelper uses for the Windows Update ticket.</summary>
    private const string WuTicketClientId = "{28520974-CE92-4F36-A219-3F255AF7E61E}";
    private const string WuTicketScope = "service::dcat.update.microsoft.com::MBI_SSL";

    /// <summary>The packages a product ships, one entry per distinct ContentId.</summary>
    public static async Task<IReadOnlyList<CatalogPackage>> GetPackagesAsync(string productId)
    {
        var handler = await QueryAsync(productId);
        var product = handler.ProductListing.Product;

        var packages = new List<CatalogPackage>();

        foreach (var availability in product.DisplaySkuAvailabilities ?? [])
        {
            var properties = availability?.Sku?.Properties;
            if (properties?.Packages is null) continue;

            // PackageFullName is routinely empty in catalog responses; the family name under
            // fulfilment data is not, and it is what the licence store records, so that is the
            // join key for matching a title to a local licence.
            var familyName = properties.FulfillmentData?.PackageFamilyName;

            foreach (var package in properties.Packages)
            {
                if (!Guid.TryParse(package?.ContentId, out var contentId)) continue;

                packages.Add(new CatalogPackage(
                    contentId,
                    familyName,
                    package.PlatformDependencies?.FirstOrDefault()?.PlatformName));
            }
        }

        return packages.DistinctBy(p => p.ContentId).ToList();
    }
}
