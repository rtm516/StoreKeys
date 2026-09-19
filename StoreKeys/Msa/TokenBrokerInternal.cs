using System.Runtime.InteropServices;
using Windows.Foundation;
using Windows.Security.Credentials;

namespace StoreKeys.Msa;

/// <summary>
/// The undocumented <c>Windows.Internal.Security.Authentication.Web.TokenBrokerInternal</c>
/// runtime class, which can enumerate the web accounts the broker knows about.
///
/// Borrowed from MCMrARM's WUTokenHelper
/// (https://github.com/MCMrARM/mc-w10-version-launcher/tree/master/WUTokenHelper), which uses it
/// to obtain a Windows Update token. The interesting part for us is not the WU token but the
/// calling pattern: it enumerates accounts with FindAllAccountsAsync and then calls
/// <c>GetTokenSilentlyAsync(request, account)</c> with an explicit account, whereas we have been
/// using the no-account overload. If the broker exposes an account here that the public API will
/// not surface, that is a candidate source for the Device Authorization token.
///
/// The IDL (interface 07650a66-66ea-489d-aa90-0dabc75f3567) declares six methods before the one
/// we want, so the filler entries below must stay, in order, to keep the vtable layout correct.
/// </summary>
internal static class TokenBrokerInternal
{
    private const string RuntimeClass = "Windows.Internal.Security.Authentication.Web.TokenBrokerInternal";

    private static readonly Guid StaticsIid = new("07650a66-66ea-489d-aa90-0dabc75f3567");

    // IInspectable occupies slots 0-5 (QueryInterface, AddRef, Release, GetIids,
    // GetRuntimeClassName, GetTrustLevel). The interface's own six filler methods take 6-11, so
    // FindAllAccountsAsync lands at 12. Dispatch is done by hand because .NET dropped support
    // for marshalling ComImport interfaces declared as IInspectable.
    private const int FindAllAccountsAsyncSlot = 12;

    public static async Task<IReadOnlyList<WebAccount>> FindAllAccountsAsync()
    {
        var iid = StaticsIid;
        var factory = GetActivationFactory(RuntimeClass, iid);

        try
        {
            var abi = InvokeFindAllAccounts(factory);
            var operation = WinRT.MarshalInterface<IAsyncOperation<IReadOnlyList<WebAccount>>>.FromAbi(abi);
            return await operation;
        }
        finally
        {
            Marshal.Release(factory);
        }
    }

    private static unsafe IntPtr InvokeFindAllAccounts(IntPtr factory)
    {
        var vtable = *(IntPtr**)factory;
        var method = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)vtable[FindAllAccountsAsyncSlot];

        IntPtr operation;
        Check(method(factory, &operation), "ITokenBrokerInternalStatics::FindAllAccountsAsync");

        return operation;
    }

    private static IntPtr GetActivationFactory(string runtimeClass, Guid iid)
    {
        var hstring = IntPtr.Zero;
        try
        {
            Check(WindowsCreateString(runtimeClass, runtimeClass.Length, out hstring),
                $"WindowsCreateString({runtimeClass})");

            Check(RoGetActivationFactory(hstring, ref iid, out var factory),
                $"RoGetActivationFactory({runtimeClass}) - the class may not exist on this build");

            return factory;
        }
        finally
        {
            if (hstring != IntPtr.Zero)
                WindowsDeleteString(hstring);
        }
    }

    private static void Check(int hr, string what)
    {
        if (hr < 0)
            throw new InvalidOperationException($"{what} failed with 0x{hr:X8}.", Marshal.GetExceptionForHR(hr));
    }

    [DllImport("combase.dll", CharSet = CharSet.Unicode)]
    private static extern int WindowsCreateString(string sourceString, int length, out IntPtr hstring);

    [DllImport("combase.dll")]
    private static extern int WindowsDeleteString(IntPtr hstring);

    [DllImport("combase.dll")]
    private static extern int RoGetActivationFactory(IntPtr activatableClassId, ref Guid iid, out IntPtr factory);
}
