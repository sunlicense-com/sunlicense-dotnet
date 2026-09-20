# SunLicense — .NET Client

Official .NET client for [SunLicense](https://sunlicense.com), a licence management and
anti-piracy system for indie software developers.

SunLicense issues, validates and revokes licence keys for FiveM scripts, desktop
applications, Minecraft plugins, Discord bots and other paid software — with marketplace
automation for BuiltByBit and Polymart.

> **Early release.** Licence validation works today. Activations, entitlements and offline
> verification are in active development.

## Install

```bash
dotnet add package SunLicense
```

## Usage

```csharp
using SunLicense;

using var client = new SunLicenseClient(
    "https://your-instance.example.com",
    token: Environment.GetEnvironmentVariable("SUNLICENSE_TOKEN")); // optional

var result = await client.ValidateAsync("LICENCE-KEY-HERE");

if (result.IsValid)
{
    Console.WriteLine("Licence valid");
}
else
{
    Console.WriteLine($"Rejected: {result.StatusCode} {result.Body}");
}
```

With extra context:

```csharp
await client.ValidateAsync("LICENCE-KEY-HERE", new Dictionary<string, string>
{
    ["product"] = "my-script",
    ["host"] = "server-01",
});
```

Reusing an existing `HttpClient` (recommended in long-running apps):

```csharp
var client = new SunLicenseClient(httpClient, "https://your-instance.example.com");
```

## Requirements

**.NET Standard 2.0** — works with .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5–10, Mono
and Unity.

No third-party dependencies, so it ships cleanly inside a FiveM resource without assembly
conflicts.

## Other clients

Also available for **Java**, **JavaScript**, **Python**, **PHP** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-dotnet/issues

## Licence

MIT © Hapangama
