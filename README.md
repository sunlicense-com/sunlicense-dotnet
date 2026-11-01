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

## Built-in analytics

Reports anonymous usage statistics for your product's **Analytics** tab (installs, versions, OS, .NET,
platform), plus your own feature usage and charts. Like bStats, for every product.

```csharp
// A licensed product: the API key, license key and machine id it validates with.
using var analytics = client.Analytics(licenseKey, machineId,
    new SunLicenseAnalyticsOptions { ProductVersion = "2.3.1", Enabled = config.Analytics });
// A free product, no license: its public product analytics id (Product → Analytics).
using var analytics = SunLicenseAnalytics.ForProduct("pa_7Hk2mQ9xZr4LbN8vT1wYcD");

analytics.Feature("auto-sell");                               // feature usage
analytics.SimplePie("storage", () => config.Storage);         // custom charts
analytics.SingleLine("players", () => Players.Count);
```

Charts: `SimplePie`, `AdvancedPie`, `DrilldownPie`, `SingleLine`, `MultiLine`, `SimpleBar`, `AdvancedBar`,
`RemoveChart`. Ids and feature names: `[a-z0-9][a-z0-9._-]{0,47}`. Callbacks run on a thread-pool timer before
each report; one that throws or returns nothing is left out. Dispose the reporter on shutdown.

**What is sent** (raw values; SunLicense groups them, e.g. `5.15.0-1051-oracle` into Linux 5.15): your
product version, the OS and its version, CPU architecture, CPU cores, locale, runtime (`dotnet` or `mono`) and version, the platform (`fivem` or `redm` with the server build, `discord` with the Discord.Net/DSharpPlus version, `unity`, else `standalone`),
the SDK's name and version, and the identity: licensed = license key + machine id (with the API key), free =
the product analytics id + a random install id kept in `.sunlicense-install-id` in `DataDirectory` (default `~/.sunlicense`). The country comes from SunLicense's edge, not
from the SDK. Nothing personal is sent: no user, host, server or player names, IP addresses or file paths.

**Switching it off.** Nothing is sent, not even an empty report, while any of these says so (checked before
every report): your product's own switch (`Enabled = false`, or `EnabledProvider` read before each report); the environment variable `SUNLICENSE_ANALYTICS=off` (also
`false` or `0`); the runtime setting `sunlicense.analytics` = `false` (runtimeconfig.json `configProperties`); on FiveM the convar `sunlicense_analytics`.

The first report goes 1 to 30 minutes after start (random), then one every 30 minutes. When
SunLicense answers with `Retry-After` (analytics switched off for the product, rate limits) it waits that long,
at most 24 hours. Reporting never runs on the license check's path, never delays or fails a check, and swallows
its own errors.

Docs: https://docs.sunlicense.com/guide/sdks#built-in-analytics

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

## Changelog

- **0.1.0**: built-in product analytics (opt-out), feature usage and custom charts: `client.Analytics()`, `SunLicenseAnalytics.ForProduct()`.

## Tests

```bash
dotnet run --project tests/SunLicense.Tests
```

## Licence

MIT © Hapangama
