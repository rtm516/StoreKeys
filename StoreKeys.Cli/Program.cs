using StoreKeys;

namespace StoreKeys.Cli;

/// <summary>
/// Thin shell over the StoreKeys library. Everything here is presentation and file I/O - the
/// library deliberately does neither.
/// </summary>
internal static class Program
{
    private const string CredentialFile = "device.json";
    private const string CikDirectory = "Cik";

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0) { Usage(); return 1; }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "cik" => await CikCommand(args[1..]),
                "contentid" => await ContentIdCommand(args[1..]),
                "devicekey" => await DeviceKeyCommand(args[1..]),
                _ => Unknown(args[0]),
            };
        }
        catch (StoreKeysException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"Unknown command '{command}'.");
        Usage();
        return 1;
    }

    private static void Usage()
    {
        Console.WriteLine("storekeys - recover XVC/XVD content keys for Store titles you own");
        Console.WriteLine();
        Console.WriteLine("  cik <contentId | product id | store url | xvc file | url>");
        Console.WriteLine("      Write keys to Cik/<keyid>.cik. Asks the licensing service, which covers");
        Console.WriteLine($"      anything your account owns, installed here or not. Uses {CredentialFile}.");
        Console.WriteLine();
        Console.WriteLine("  contentid <product id | store url | xvc file | url>");
        Console.WriteLine("      Print the ContentId(s) the licensing service keys off.");
        Console.WriteLine();
        Console.WriteLine("  devicekey");
        Console.WriteLine($"      Show the credential in {CredentialFile}. Keys arrive wrapped under it,");
        Console.WriteLine("      so one is needed once and then reused.");
        Console.WriteLine();
        Console.WriteLine("  devicekey --fromdevice [--force]");
        Console.WriteLine("      Derive this machine's device key from its licence store. Needs elevation.");
        Console.WriteLine();
        Console.WriteLine("  devicekey --newdevice [--force]");
        Console.WriteLine("      Register a new device identity with MSA instead. No elevation and no");
        Console.WriteLine("      prompts, so it works without admin rights - but it creates a device");
        Console.WriteLine("      registration on Microsoft's identity service.");
    }

    // ----------------------------------------------------------------- cik

    private static async Task<int> CikCommand(string[] args)
    {
        var target = args.FirstOrDefault(a => !a.StartsWith('-'));

        if (target is null)
        {
            Console.Error.WriteLine("Need a contentId, product id, store URL, xvc file or URL.");
            return 1;
        }

        var content = await StoreContent.FromAsync(target);
        Describe(content);

        if (content.IsXboxOnly)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("This title ships only for Xbox consoles. There is no PC package to license,");
            Console.Error.WriteLine("the licensing service refuses a PC identity for console content, and console");
            Console.Error.WriteLine("keys are wrapped under the ODK rather than a device key. Getting one needs");
            Console.Error.WriteLine("a console.");
            return 1;
        }

        var keys = await content.FetchCikAsync(ResolveCredential());
        return WriteKeys(keys);
    }

    // ----------------------------------------------------------- contentid

    private static async Task<int> ContentIdCommand(string[] args)
    {
        if (args.Length == 0) { Console.Error.WriteLine("Need a product id, store URL, file or URL."); return 1; }

        var content = await StoreContent.FromAsync(args[0]);
        Describe(content);

        foreach (var contentId in content.ContentIds)
            Console.WriteLine(contentId);

        return 0;
    }

    // ----------------------------------------------------------- devicekey

    private static async Task<int> DeviceKeyCommand(string[] args)
    {
        var fromDevice = args.Contains("--fromdevice");
        var newDevice = args.Contains("--newdevice");

        if (fromDevice && newDevice)
        {
            Console.Error.WriteLine("Pick one of --fromdevice or --newdevice.");
            return 1;
        }

        if (!fromDevice && !newDevice)
            return ShowCredential();

        if (!args.Contains("--force") && File.Exists(CredentialFile))
        {
            Console.WriteLine($"{CredentialFile} already exists. Pass --force to replace it.");
            return 0;
        }

        DeviceCredential credential;

        if (newDevice)
        {
            Console.WriteLine("Registering a new device identity with MSA.");
            Console.WriteLine("This writes to Microsoft's identity service; it is not a local operation.");
            Console.WriteLine();

            credential = await DeviceCredential.ProvisionAsync();
        }
        else
        {
            credential = DeviceCredential.FromLocalMachine();
        }

        // Written before the key is derived: a registration we cannot read back afterwards is
        // waste on the service's side.
        File.WriteAllText(CredentialFile, credential.ToJson());
        Console.WriteLine($"Device credential written to {Path.GetFullPath(CredentialFile)}");

        if (newDevice)
            Console.WriteLine("Keep it. Re-running --newdevice registers another device.");

        Console.WriteLine();
        Describe(credential);

        return 0;
    }

    /// <summary>Reports on the credential in use, without touching the network or elevating.</summary>
    private static int ShowCredential()
    {
        if (!File.Exists(CredentialFile))
        {
            Console.WriteLine($"No {CredentialFile} here.");
            Console.WriteLine();
            Console.WriteLine("  devicekey --fromdevice   derive from this machine (needs elevation)");
            Console.WriteLine("  devicekey --newdevice    register a new device identity instead");
            return 1;
        }

        var credential = DeviceCredential.FromJson(File.ReadAllText(CredentialFile));

        Console.WriteLine($"{Path.GetFullPath(CredentialFile)}");
        Console.WriteLine();
        Console.WriteLine($"  source      {(credential.IsProvisioned ? "provisioned" : "this machine")}");
        Console.WriteLine($"  created     {credential.CreatedUtc:u}");

        if (credential.IsProvisioned)
        {
            Console.WriteLine($"  membername  {credential.Membername?[..4]}... (withheld)");
            Console.WriteLine($"  licence     CLEP v{credential.DeviceLicenseVersion?.ToString() ?? "?"}");
        }

        Describe(credential);

        return 0;
    }

    /// <summary>Confirms the credential yields a key, which is the only thing that matters.</summary>
    private static void Describe(DeviceCredential credential)
    {
        try
        {
            Console.WriteLine($"  device key  {credential.DeviceKey.Length} bytes, derived");
        }
        catch (StoreKeysException ex)
        {
            Console.WriteLine($"  device key  unavailable: {ex.Message}");
        }
    }

    /// <summary>
    /// Caching the credential is the CLI's job, not the library's. Deriving it needs elevation,
    /// so it is never done implicitly in the middle of another command.
    /// </summary>
    private static DeviceCredential ResolveCredential()
    {
        if (File.Exists(CredentialFile))
            return DeviceCredential.FromJson(File.ReadAllText(CredentialFile));

        throw new StoreKeysException(
            $"No {CredentialFile} found. Run 'devicekey' once to create it (needs elevation).");
    }

    // ---------------------------------------------------------------- misc

    private static void Describe(StoreContent content)
    {
        if (content.Title is not null)
            Console.WriteLine($"{content.ProductId}: {content.Title}");

        if (content.PackageFamilyName is not null)
            Console.WriteLine($"  package family: {content.PackageFamilyName}");
    }

    private static int WriteKeys(IReadOnlyList<ContentKey> keys)
    {
        Directory.CreateDirectory(CikDirectory);

        foreach (var key in keys)
        foreach (var (keyId, contents) in key.ToCikFiles())
        {
            var path = Path.Combine(CikDirectory, $"{keyId}.cik");
            File.WriteAllBytes(path, contents);

            Console.WriteLine($"{keyId}  {key.ToHexString()}  -> {path}");
        }

        Console.WriteLine($"Copy {CikDirectory}/ next to XvdTool.Streaming.exe; it matches keys by id.");

        return 0;
    }
}
