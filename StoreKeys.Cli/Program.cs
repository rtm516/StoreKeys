using System.CommandLine;
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
        => await BuildCommandLine().Parse(args).InvokeAsync();

    private static RootCommand BuildCommandLine()
    {
        var root = new RootCommand("storekeys - recover XVC/XVD content keys for Store titles you own")
        {
            CikCommand(),
            ContentIdCommand(),
            DeviceKeyCommand(),
        };

        return root;
    }

    /// <summary>What every command that resolves content takes.</summary>
    private static Argument<string> TargetArgument() =>
        new("target")
        {
            Description = "contentId, product id, store url, xvc file or url",
        };

    // ----------------------------------------------------------------- cik

    private static Command CikCommand()
    {
        var target = TargetArgument();

        var command = new Command("cik", $"Write keys to {CikDirectory}/<keyid>.cik")
        {
            target,
        };

        command.SetAction((result, _) => Guard(() => Cik(result.GetValue(target)!)));

        return command;
    }

    private static async Task<int> Cik(string target)
    {
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

        return WriteKeys(await content.FetchCikAsync(ResolveCredential()));
    }

    // ----------------------------------------------------------- contentid

    private static Command ContentIdCommand()
    {
        var target = TargetArgument();

        var command = new Command("contentid", "Print the ContentId(s) the licensing service keys off")
        {
            target,
        };

        command.SetAction((result, _) => Guard(() => ContentId(result.GetValue(target)!)));

        return command;
    }

    private static async Task<int> ContentId(string target)
    {
        var content = await StoreContent.FromAsync(target);
        Describe(content);

        foreach (var contentId in content.ContentIds)
            Console.WriteLine(contentId);

        return 0;
    }

    // ----------------------------------------------------------- devicekey

    private static Command DeviceKeyCommand()
    {
        var fromDevice = new Option<bool>("--fromdevice")
        {
            Description = "Derive from this machine's licence store. Needs elevation.",
        };

        var newDevice = new Option<bool>("--newdevice")
        {
            Description = "Register a new device identity with MSA instead. No elevation.",
        };

        var force = new Option<bool>("--force")
        {
            Description = $"Replace an existing {CredentialFile}.",
        };

        var command = new Command("devicekey", $"Show or create the credential in {CredentialFile}")
        {
            fromDevice,
            newDevice,
            force,
        };

        command.Validators.Add(result =>
        {
            if (result.GetValue(fromDevice) && result.GetValue(newDevice))
                result.AddError("Pick one of --fromdevice or --newdevice.");
        });

        command.SetAction((result, _) => Guard(() => DeviceKey(
            result.GetValue(fromDevice),
            result.GetValue(newDevice),
            result.GetValue(force))));

        return command;
    }

    private static async Task<int> DeviceKey(bool fromDevice, bool newDevice, bool force)
    {
        if (!fromDevice && !newDevice)
            return ShowCredential();

        if (!force && File.Exists(CredentialFile))
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

    // ---------------------------------------------------------------- misc

    /// <summary>
    /// Turns a library failure into a message and an exit code. The parser handles everything
    /// that goes wrong before a command runs.
    /// </summary>
    private static async Task<int> Guard(Func<Task<int>> action)
    {
        try
        {
            return await action();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
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

    private static void Describe(StoreContent content)
    {
        if (content.Title is not null)
            Console.WriteLine($"{content.ProductId}: {content.Title}");

        if (content.PackageFamilyName is not null)
            Console.WriteLine($"  package family: {content.PackageFamilyName}");
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
            $"No {CredentialFile} found. Run 'devicekey --fromdevice' or 'devicekey --newdevice' first.");
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
