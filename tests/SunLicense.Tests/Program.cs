// Tests for built-in product analytics. Run: dotnet run --project tests/SunLicense.Tests
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SunLicense;

var failed = 0;
var count = 0;

async Task Test(string name, Func<Task> body)
{
    count++;
    try
    {
        await body();
        Console.WriteLine("ok   " + name);
    }
    catch (Exception e)
    {
        failed++;
        Console.WriteLine("FAIL " + name + ": " + e.Message);
    }
}

void Check(bool condition, string message)
{
    if (!condition)
    {
        throw new Exception(message);
    }
}

string TempDir()
{
    var dir = Path.Combine(Path.GetTempPath(), "sunlicense-analytics-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    return dir;
}

string NoEnv(string name) => null;

SunLicenseAnalytics Make(SunLicenseAnalyticsOptions o, Recorder recorder)
{
    o.Env ??= NoEnv;
    o.DataDirectory ??= TempDir();
    o.Transport = recorder.Post;
    return SunLicenseAnalytics.Create(o);
}

// SunLicense's conformance fixtures (spec 185 section 4.8,
// analytics-service/src/test/resources/conformance/reports.json): copy the file again when it changes.
var fixtures = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "conformance-reports.json")));

foreach (var c in fixtures["cases"].AsArray())
{
    await Test($"conformance: sends the request side of \"{c["name"]}\"", async () =>
    {
        var r = c["report"].AsObject();
        var licensed = c["licensed"].GetValue<bool>();
        var system = new Dictionary<string, object>();
        string productVersion = null;
        foreach (var pair in r["metrics"]?.AsObject() ?? new JsonObject())
        {
            if (pair.Key == "productVersion")
            {
                productVersion = pair.Value.GetValue<string>();
            }
            else
            {
                system[pair.Key] = pair.Value.GetValueKind() == System.Text.Json.JsonValueKind.Number ? pair.Value.GetValue<int>() : pair.Value.GetValue<string>();
            }
        }

        var dir = TempDir();
        if (r["installId"] != null)
        {
            File.WriteAllText(Path.Combine(dir, ".sunlicense-install-id"), r["installId"].GetValue<string>());
        }

        var recorder = new Recorder();
        var analytics = Make(new SunLicenseAnalyticsOptions
        {
            BaseUrl = "https://api.example.test/",
            ApiKey = licensed ? "slk_test" : null,
            LicenseKey = r["licenseKey"]?.GetValue<string>(),
            Fingerprint = r["fingerprint"]?.GetValue<string>(),
            ProductAnalyticsId = r["productAnalyticsId"]?.GetValue<string>(),
            DataDirectory = dir,
            ProductVersion = productVersion,
            Collect = () => system,
        }, recorder);
        Check(await analytics.SendNowAsync() == 204, "expected 204");
        var sent = recorder.Seen[0];
        Check(sent.Url == "https://api.example.test/api/v2/analytics/report", "url " + sent.Url);
        var expected = r.DeepClone().AsObject();
        expected["schema"] = 1;
        expected["sdk"] = new JsonObject { ["name"] = "csharp", ["version"] = SunLicenseClient.Version };
        Check(JsonNode.DeepEquals(sent.Body, expected), $"body {sent.Body.ToJsonString()} != {expected.ToJsonString()}");
        Check(sent.Headers.GetValueOrDefault("Authorization") == (licensed ? "Bearer slk_test" : null), "Authorization header");
        Check(Regex.IsMatch(sent.Headers["User-Agent"], @"^sunlicense-dotnet/\d+\.\d+\.\d+ analytics$"), "User-Agent");
    });
}

await Test("collects raw built-in metrics from this machine, nothing personal", async () =>
{
    var recorder = new Recorder();
    await Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x", ProductVersion = "v1.2.3" }, recorder).SendNowAsync();
    var m = recorder.Seen[0].Body["metrics"];
    Check(m["productVersion"].GetValue<string>() == "v1.2.3", "productVersion");
    Check(m["runtime"].GetValue<string>() == "dotnet" && m["runtimeVersion"].GetValue<string>().StartsWith(Environment.Version.Major + "."), "runtime " + m["runtimeVersion"]);
    Check(m["platform"].GetValue<string>() == "standalone" && m["cores"].GetValue<int>() >= 1, "platform, cores");
    Check(m["os"] != null && m["arch"] != null, "os, arch");
    var raw = recorder.Seen[0].Raw;
    foreach (var personal in new[] { Environment.MachineName, Environment.UserName, Environment.CurrentDirectory, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) })
    {
        Check(string.IsNullOrEmpty(personal) || !raw.Contains(personal), "report contains " + personal);
    }
});

await Test("client.Analytics uses the client base URL and API key; ForProduct takes a product analytics id", async () =>
{
    var client = new SunLicenseClient("https://api.example.test/", token: "slk_x");
    using var a = client.Analytics("K", "f", new SunLicenseAnalyticsOptions { Enabled = false });
    Check(!a.IsEnabled, "switch");
    using var free = SunLicenseAnalytics.ForProduct("pa_abc", new SunLicenseAnalyticsOptions { Enabled = false });
    Check(!free.IsEnabled, "switch");
    var recorder = new Recorder();
    var o = new SunLicenseAnalyticsOptions { LicenseKey = "K", Fingerprint = "f", Env = NoEnv, Transport = recorder.Post, DataDirectory = TempDir(), FirstDelay = TimeSpan.FromDays(1) };
    using var licensed = client.Analytics("K", "f", o);
    Check(await licensed.SendNowAsync() == 204, "204");
    Check(recorder.Seen[0].Url == "https://api.example.test/api/v2/analytics/report", "url");
    Check(recorder.Seen[0].Headers["Authorization"] == "Bearer slk_x", "API key");
    Check(recorder.Seen[0].Body["installId"] == null, "no install id with only a license");
});

await Test("opt-out: product switch, environment, runtime setting; nothing is sent", async () =>
{
    var cases = new List<SunLicenseAnalyticsOptions>
    {
        new SunLicenseAnalyticsOptions { Enabled = false },
        new SunLicenseAnalyticsOptions { EnabledProvider = () => false },
        new SunLicenseAnalyticsOptions { EnabledProvider = () => throw new InvalidOperationException("config gone") },
        new SunLicenseAnalyticsOptions { Env = n => n == "SUNLICENSE_ANALYTICS" ? "off" : null },
        new SunLicenseAnalyticsOptions { Env = n => n == "SUNLICENSE_ANALYTICS" ? " FALSE " : null },
        new SunLicenseAnalyticsOptions { Env = n => n == "SUNLICENSE_ANALYTICS" ? "0" : null },
    };
    foreach (var o in cases)
    {
        var recorder = new Recorder();
        o.ProductAnalyticsId = "pa_x";
        var a = Make(o, recorder);
        Check(!a.IsEnabled, "off");
        Check(await a.SendNowAsync() == 0 && recorder.Seen.Count == 0, "nothing sent");
    }

    AppContext.SetData("sunlicense.analytics", "false");
    var r2 = new Recorder();
    Check(await Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, r2).SendNowAsync() == 0, "runtime setting off");
    AppContext.SetData("sunlicense.analytics", null);
    var on = false;
    var r3 = new Recorder();
    var later = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x", EnabledProvider = () => on }, r3);
    Check(await later.SendNowAsync() == 0, "off");
    on = true;
    Check(await later.SendNowAsync() == 204, "switched on at runtime");
});

await Test("identity: nothing sent without one; licensed needs API key, license key and machine id", async () =>
{
    var recorder = new Recorder();
    Check(await Make(new SunLicenseAnalyticsOptions(), recorder).SendNowAsync() == 0, "none");
    Check(await Make(new SunLicenseAnalyticsOptions { ApiKey = "slk", Fingerprint = "f" }, recorder).SendNowAsync() == 0, "no key");
    string key = null;
    var a = Make(new SunLicenseAnalyticsOptions { ApiKey = "slk", Fingerprint = "f", LicenseKeyProvider = () => key }, recorder);
    Check(await a.SendNowAsync() == 0, "no key yet");
    key = " AX8P-4Q2M ";
    Check(await a.SendNowAsync() == 204 && recorder.Seen[0].Body["licenseKey"].GetValue<string>() == "AX8P-4Q2M", "key");
});

await Test("never throws: a transport that throws, broken suppliers, null options", async () =>
{
    var a = SunLicenseAnalytics.Create(new SunLicenseAnalyticsOptions
    {
        ProductAnalyticsId = "pa_x", DataDirectory = TempDir(), Env = NoEnv,
        ProductVersionProvider = () => throw new InvalidOperationException("x"),
        Transport = (u, h, b) => throw new WebException("network down"),
    });
    Check(await a.SendNowAsync() == -1, "no answer");
    using var b = SunLicenseAnalytics.Start(null);
    Check(await b.SendNowAsync() == 0, "nothing to send");
});

await Test("schedule: 1-30 minutes first, then 30 minutes; Retry-After between 1 minute and 24 hours", () =>
{
    Check(SunLicenseAnalytics.FirstDelay(new Fixed(0)) == TimeSpan.FromMinutes(1), "1 minute");
    Check(SunLicenseAnalytics.FirstDelay(new Fixed(0.9999999)) == TimeSpan.FromMinutes(30), "30 minutes");
    Check(SunLicenseAnalytics.NextDelay(204, "86400") == TimeSpan.FromMinutes(30), "204");
    Check(SunLicenseAnalytics.NextDelay(-1, null) == TimeSpan.FromMinutes(30), "no answer");
    Check(SunLicenseAnalytics.NextDelay(429, "120") == TimeSpan.FromMinutes(2), "120 s");
    Check(SunLicenseAnalytics.NextDelay(429, "5") == TimeSpan.FromMinutes(1), "min");
    Check(SunLicenseAnalytics.NextDelay(403, "999999") == TimeSpan.FromHours(24), "max");
    Check(SunLicenseAnalytics.NextDelay(503, "Wed, 21 Oct 2026 07:28:00 GMT") == TimeSpan.FromMinutes(30), "date");
    return Task.CompletedTask;
});

await Test("install id: created once and kept", async () =>
{
    var dir = TempDir();
    var recorder = new Recorder();
    await Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x", DataDirectory = dir }, recorder).SendNowAsync();
    await Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x", DataDirectory = dir }, recorder).SendNowAsync();
    var id = File.ReadAllText(Path.Combine(dir, ".sunlicense-install-id"));
    Check(Regex.IsMatch(id, "^[A-Za-z0-9_-]{8,64}$"), "id " + id);
    Check(recorder.Seen.All(s => s.Body["installId"].GetValue<string>() == id), "kept");
});

await Test("features: counted, sent, kept until stored; nothing counted while off", async () =>
{
    var recorder = new Recorder { Status = 503, RetryAfter = "60" };
    var a = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, recorder);
    a.Feature("auto-sell").Feature("Auto-Sell", 2).Feature("web-editor").Feature("bad name!").Feature("x", 0).Feature(null);
    Check(await a.SendNowAsync() == 503, "503");
    Check(JsonNode.DeepEquals(recorder.Seen[0].Body["features"], JsonNode.Parse("{\"auto-sell\":3,\"web-editor\":1}")), recorder.Seen[0].Raw);
    a.Feature("auto-sell");
    recorder.Status = 204;
    Check(await a.SendNowAsync() == 204, "204");
    Check(JsonNode.DeepEquals(recorder.Seen[1].Body["features"], JsonNode.Parse("{\"auto-sell\":4,\"web-editor\":1}")), "kept");
    await a.SendNowAsync();
    Check(recorder.Seen[2].Body["features"] == null, "gone");
    var on = false;
    var r2 = new Recorder();
    var later = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x", EnabledProvider = () => on }, r2);
    later.Feature("auto-sell");
    on = true;
    await later.SendNowAsync();
    Check(r2.Seen[0].Body["features"] == null, "nothing counted while off");
});

await Test("features: at most 50 per report, the rest wait", async () =>
{
    var recorder = new Recorder();
    var a = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, recorder);
    for (var i = 0; i < 60; i++)
    {
        a.Feature("f" + i);
    }

    await a.SendNowAsync();
    await a.SendNowAsync();
    Check(recorder.Seen[0].Body["features"].AsObject().Count == 50 && recorder.Seen[1].Body["features"].AsObject().Count == 10, "50 + 10");
});

await Test("custom charts: every type, the wire shape of spec 185 section 4.6", async () =>
{
    var recorder = new Recorder();
    var a = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, recorder)
        .SimplePie("storage", () => "mysql")
        .AdvancedPie("modules", () => new Dictionary<string, int> { ["shop"] = 2, ["auctions"] = 1, ["zero"] = 0 })
        .DrilldownPie("java", () => new Dictionary<string, IDictionary<string, int>>
        {
            ["Java 21"] = new Dictionary<string, int> { ["21.0.4"] = 1 },
            ["empty"] = new Dictionary<string, int>(),
        })
        .SingleLine("players", () => 42)
        .MultiLine("worlds", () => new Dictionary<string, int> { ["overworld"] = 30, ["nether"] = -2 })
        .SimpleBar("commands", () => new Dictionary<string, int> { ["sell"] = 12 })
        .AdvancedBar("tiers", () => new Dictionary<string, int[]> { ["gold"] = new[] { 1, 2, 3 }, ["empty"] = new int[0] })
        .SimplePie("nothing", () => null)
        .SimplePie("empty", () => "  ")
        .SingleLine("huge", () => 2000000000)
        .SingleLine("none", () => null)
        .SimplePie("throws", () => throw new InvalidOperationException("x"))
        .SimplePie("Bad Id", () => "x")
        .SimplePie("removed", () => "x")
        .RemoveChart("removed");
    Check(await a.SendNowAsync() == 204, "204");
    var expected = JsonNode.Parse(@"[
        {""id"":""storage"",""type"":""simple_pie"",""data"":{""value"":""mysql""}},
        {""id"":""modules"",""type"":""advanced_pie"",""data"":{""values"":{""shop"":2,""auctions"":1}}},
        {""id"":""java"",""type"":""drilldown_pie"",""data"":{""values"":{""Java 21"":{""21.0.4"":1}}}},
        {""id"":""players"",""type"":""single_line"",""data"":{""value"":42}},
        {""id"":""worlds"",""type"":""multi_line"",""data"":{""values"":{""overworld"":30,""nether"":-2}}},
        {""id"":""commands"",""type"":""simple_bar"",""data"":{""values"":{""sell"":12}}},
        {""id"":""tiers"",""type"":""advanced_bar"",""data"":{""values"":{""gold"":[1,2,3]}}}]");
    Check(JsonNode.DeepEquals(recorder.Seen[0].Body["charts"], expected), recorder.Seen[0].Body["charts"].ToJsonString());
});

await Test("custom charts: same id replaces, at most 30; a report over 16 KB keeps the built-ins", async () =>
{
    var recorder = new Recorder();
    var a = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, recorder);
    a.SimplePie("storage", () => "mysql").SimplePie("STORAGE", () => "sqlite");
    for (var i = 0; i < 40; i++)
    {
        var n = i;
        a.SingleLine("c" + i, () => n);
    }

    await a.SendNowAsync();
    var charts = recorder.Seen[0].Body["charts"].AsArray();
    Check(charts.Count == 30 && charts[0]["data"]["value"].GetValue<string>() == "sqlite", "30, replaced");
    var big = Make(new SunLicenseAnalyticsOptions { ProductAnalyticsId = "pa_x" }, recorder);
    for (var i = 0; i < 30; i++)
    {
        big.AdvancedPie("big" + i, () => Enumerable.Range(1, 50).ToDictionary(j => new string('v', 40) + j, j => j));
    }

    big.Feature("kept");
    Check(await big.SendNowAsync() == 204, "204");
    var body = recorder.Seen[1].Body;
    Check(body["charts"] == null && body["features"] == null && body["metrics"] != null, "stripped");
    await big.SendNowAsync();
    Check(recorder.Seen[2].Raw.Length > 0, "still sends");
});

await Test("reports in the background to a real HTTP server, and Dispose stops it", async () =>
{
    var listener = new HttpListener();
    var port = new Random().Next(20000, 40000);
    listener.Prefixes.Add($"http://127.0.0.1:{port}/");
    listener.Start();
    var received = new TaskCompletionSource<(string Path, string Body, string Agent)>();
    _ = Task.Run(async () =>
    {
        var context = await listener.GetContextAsync();
        using var reader = new StreamReader(context.Request.InputStream);
        var text = await reader.ReadToEndAsync();
        context.Response.StatusCode = 204;
        context.Response.Close();
        received.TrySetResult((context.Request.Url.AbsolutePath, text, context.Request.UserAgent));
    });
    using (var a = SunLicenseAnalytics.Start(new SunLicenseAnalyticsOptions
    {
        BaseUrl = $"http://127.0.0.1:{port}", ProductAnalyticsId = "pa_bg", DataDirectory = TempDir(), Env = NoEnv,
        FirstDelay = TimeSpan.FromMilliseconds(10),
    }))
    {
        var done = await Task.WhenAny(received.Task, Task.Delay(5000));
        Check(done == received.Task, "no report within 5 s");
    }

    listener.Stop();
    var (path, body, agent) = received.Task.Result;
    Check(path == "/api/v2/analytics/report", "path " + path);
    Check(JsonNode.Parse(body)["productAnalyticsId"].GetValue<string>() == "pa_bg", "body");
    Check(agent.StartsWith("sunlicense-dotnet/"), "User-Agent");
});

Console.WriteLine($"{count} tests, {failed} failed");
return failed == 0 ? 0 : 1;

sealed class Recorder
{
    public int Status { get; set; } = 204;

    public string RetryAfter { get; set; }

    public List<(string Url, Dictionary<string, string> Headers, JsonNode Body, string Raw)> Seen { get; } = new();

    public Task<SunLicenseAnalytics.Answer> Post(string url, IDictionary<string, string> headers, string body)
    {
        Seen.Add((url, new Dictionary<string, string>(headers), JsonNode.Parse(body), body));
        return Task.FromResult(new SunLicenseAnalytics.Answer(Status, RetryAfter));
    }
}

sealed class Fixed : Random
{
    private readonly double _value;

    public Fixed(double value) => _value = value;

    public override int Next(int maxValue) => (int)(_value * maxValue);

    protected override double Sample() => _value;
}
