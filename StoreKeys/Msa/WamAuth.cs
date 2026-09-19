using Windows.Security.Authentication.Web.Core;
using Windows.Security.Credentials;

namespace StoreKeys.Msa;

/// <summary>
/// User-ticket acquisition through the Web Account Manager, which is what the OS itself uses.
///
/// LicenseManager.dll references Windows.Security.Authentication.Web.Core.WebTokenRequest,
/// WebTokenRequestStatus and the MSA provider pair "https://login.microsoft.com" + "consumers",
/// so this mirrors the OS path.
///
/// This yields the *user* ticket that goes in the request body. It cannot produce the Device
/// Authorization token the Authorization header needs - that was probed exhaustively across
/// client ids, scope policies, request properties, explicit broker accounts and MSIX package
/// identity, and every combination returns a user ticket. See the README.
/// </summary>
internal static class WamAuth
{
    public const string MsaAuthority = "https://login.microsoft.com";
    public const string ConsumersAuthority = "consumers";

    public static async Task<WebAccountProvider> GetMsaProviderAsync()
    {
        var provider = await WebAuthenticationCoreManager.FindAccountProviderAsync(MsaAuthority, ConsumersAuthority);
        return provider
               ?? throw new InvalidOperationException(
                   "No Microsoft account provider available. Sign in to Windows with your Microsoft account, " +
                   "or add it under Settings > Accounts > Email & accounts.");
    }

    /// <summary>
    /// Silent token request against the signed-in Windows account. Interactive brokering is not
    /// attempted: from an unpackaged console process it needs the
    /// IWebAuthenticationCoreManagerInterop window hook, and if the account is already on the
    /// machine the silent path is what the OS uses anyway.
    /// </summary>
    public static async Task<string> GetTokenAsync(
        string clientId = MsaAuth.BrokerClientId,
        string scope = MsaAuth.LicensingScope)
    {
        var provider = await GetMsaProviderAsync();
        var request = new WebTokenRequest(provider, scope, clientId);

        var result = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request);

        if (result.ResponseStatus == WebTokenRequestStatus.UserInteractionRequired)
            throw new InvalidOperationException(
                $"{Describe(result)}. The broker wants an interactive sign-in: open the Microsoft Store " +
                "or Xbox app once, sign in, then retry.");

        if (result.ResponseStatus != WebTokenRequestStatus.Success)
            throw new InvalidOperationException(Describe(result));

        return result.ResponseData[0].Token;
    }

    private static string Describe(WebTokenRequestResult result)
    {
        var error = result.ResponseError;
        return error is null
            ? result.ResponseStatus.ToString()
            : $"{result.ResponseStatus} (0x{error.ErrorCode:X8}) {error.ErrorMessage}";
    }
}
