using StoreKeys;

namespace StoreKeys.Cli;

/// <summary>
/// Thin shell over the StoreKeys library. Everything here is presentation and file I/O - the
/// library deliberately does neither.
/// </summary>
internal static class Program
{
    private const string DeviceKeyFile = "deviceKey.txt";
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
                "devicekey" => DeviceKeyCommand(args[1..]),
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
        Console.WriteLine("  cik <contentId | product id | store url | xvc file | url> [--device-key <hex|path>]");
        Console.WriteLine("      Write keys to Cik/<keyid>.cik. Asks the licensing service, which covers");
        Console.WriteLine($"      anything your account owns, installed here or not. Uses {DeviceKeyFile}");
        Console.WriteLine("      unless --device-key is given.");
        Console.WriteLine();
        Console.WriteLine("  contentid <product id | store url | xvc file | url>");
        Console.WriteLine("      Print the ContentId(s) the licensing service keys off.");
        Console.WriteLine();
        Console.WriteLine("  devicekey [--force]");
        Console.WriteLine($"      Derive this machine's device key into {DeviceKeyFile}. Needs elevation.");
        Console.WriteLine("      Keys arrive wrapped under it, so it is needed once and then reused.");
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

        var keys = await content.FetchCikAsync(ResolveDeviceKey(args));
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

    private static int DeviceKeyCommand(string[] args)
    {
        if (!args.Contains("--force") && File.Exists(DeviceKeyFile))
        {
            Console.WriteLine($"{DeviceKeyFile} already exists. Pass --force to derive it again.");
            return 0;
        }

        var key = DeviceKey.Derive();
        File.WriteAllText(DeviceKeyFile, Convert.ToHexString(key));

        Console.WriteLine($"Device key written to {Path.GetFullPath(DeviceKeyFile)}");
        return 0;
    }

    /// <summary>
    /// Caching the device key is the CLI's job, not the library's. Deriving it needs elevation,
    /// so it is never done implicitly in the middle of another command.
    /// </summary>
    private static byte[] ResolveDeviceKey(string[] args)
    {
        var index = Array.IndexOf(args, "--device-key");
        if (index >= 0 && index + 1 < args.Length)
        {
            var value = args[index + 1];
            return DeviceKey.Parse(File.Exists(value) ? File.ReadAllText(value) : value);
        }

        if (File.Exists(DeviceKeyFile))
            return DeviceKey.Parse(File.ReadAllText(DeviceKeyFile));

        throw new StoreKeysException(
            $"No {DeviceKeyFile} found. Run 'devicekey' once to derive it (needs elevation), "
            + "or pass --device-key <hex|path>.");
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
