# StoreKeys

Recover MSIXVC/XVC content keys (CIKs) for Microsoft Store titles you own, so
[XvdTool.Streaming](https://github.com/LukeFZ/XvdTool.Streaming) can decrypt them - **without
needing the game installed**.

Keys come from the Store licensing service, so this covers anything your account is entitled to.
The only local step is deriving this machine's device key, which every licence is wrapped under.

Windows only: the device key comes out of the licence store, and authentication goes through the
Web Account Manager.

## Library

```csharp
using StoreKeys;

// One-time; needs elevation. Cache it yourself - the library never writes to disk.
byte[] deviceKey = DeviceKey.Derive();

var content = await StoreContent.FromUrlAsync("https://www.xbox.com/en-GB/games/store/minecraft-for-windows/9nblggh2jhxj");
var keys    = await content.FetchCikAsync(deviceKey);

foreach (var (keyId, bytes) in keys.SelectMany(k => k.ToCikFiles()))
    File.WriteAllBytes($"Cik/{keyId}.cik", bytes);
```

Resolve from whatever you have:

```csharp
StoreContent.FromFile("Minecraft....msixvc").ContentId     // XVD header, VDUID at 0x220
StoreContent.FromContentId(guid)
await StoreContent.FromProductIdAsync("9nblggh2jhxj")
await StoreContent.FromUrlAsync(storePageOrXvcUrl)
await StoreContent.FromAsync(anyOfTheAbove)
```

List the packages a key opens:

```csharp
foreach (var package in await content.FetchPackagesAsync())
    Console.WriteLine($"{package.Identifier}  {package.DownloadUrl}");
```

## CLI

```bash
# One-time: derive this machine's device key into deviceKey.txt. Needs elevation.
StoreKeys.Cli devicekey

StoreKeys.Cli cik https://www.xbox.com/en-GB/games/store/minecraft-for-windows/9nblggh2jhxj
StoreKeys.Cli cik 9nblggh2jhxj
StoreKeys.Cli cik 7792d9ce-355a-493c-afbd-768f4a77c3b0
StoreKeys.Cli cik Microsoft.MinecraftUWP_..._x64__8wekyb3d8bbwe.msixvc

StoreKeys.Cli contentid 9nblggh2jhxj
```

## Licence

GPL-3.0-only - see `LICENSE`.

The `StoreKeys` package embeds `LibXboxOne.dll` (GPL-2.0), `StoreLib.dll` (MPL-2.0) and
`LibCikExtractor.dll` (MIT), since none are published to NuGet.

## How it works

The licensing protocol, the device identity, and what was verified against real data are written
up in [docs/protocol.md](docs/protocol.md).

Building from source: clone with `--recurse-submodules`.

Built with [Claude Code](https://claude.com/claude-code).
