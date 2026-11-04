// Tests for core unlock, integrity, the notice and protected files: SunLicense's protection test vectors
// (fixtures/protection-test-vectors.json, a copy of cloud/docs/specs/protection-test-vectors.json) and the cache rules.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using SunLicense;

static class ProtectionTests
{
    const string Key = "AX8P-QW3E-RT5Y-ZZ12";
    static readonly DateTimeOffset T0 = DateTimeOffset.FromUnixTimeMilliseconds(1762000000000);

    static int count;
    static int failed;

    static async Task Test(string name, Func<Task> body)
    {
        count++;
        try
        {
            await body();
            Console.WriteLine("ok   protection: " + name);
        }
        catch (Exception e)
        {
            failed++;
            Console.WriteLine("FAIL protection: " + name + ": " + e.Message);
        }
    }

    static Task Test(string name, Action body) => Test(name, () => { body(); return Task.CompletedTask; });

    static void Check(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }

    static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sunlicense-protection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    static byte[] Unhex(string h) => Convert.FromHexString(h);

    sealed class Clock
    {
        public DateTimeOffset T = T0;
    }

    static SunLicenseProtection Make(string dir = null, Clock clock = null, string machine = "host-a", string fingerprint = "machine-1",
        string licenseKey = Key, Action<SunLicenseProtectionOptions> more = null)
    {
        clock ??= new Clock();
        var o = new SunLicenseProtectionOptions
        {
            LicenseKey = licenseKey, Fingerprint = fingerprint, BaseUrl = "https://api.example.test",
            CacheDirectory = dir ?? TempDir(), Now = () => clock.T, Machine = () => machine,
        };
        more?.Invoke(o);
        return new SunLicenseProtection(o);
    }

    public static async Task<(int, int)> Run()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "protection-test-vectors.json")));
        var unlock = v["wire"]["compatResponseV2"]["unlock"].GetValue<string>();
        var compat = v["wire"]["compatResponseV2"].ToJsonString();

        await Test("HKDF matches RFC 5869 test case 1 and the product keys", () =>
        {
            var t = v["rfc5869TestCase1"];
            var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, Unhex(t["ikmHex"].GetValue<string>()), t["length"].GetValue<int>(),
                Unhex(t["saltHex"].GetValue<string>()), Unhex(t["infoHex"].GetValue<string>()));
            Check(Convert.ToHexString(okm).ToLowerInvariant() == t["okmHex"].GetValue<string>(), "okm");
            foreach (var k in v["productKeys"].AsArray())
            {
                var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, Unhex(k["orgSecretHex"].GetValue<string>()), 32,
                    Encoding.ASCII.GetBytes(k["saltAscii"].GetValue<string>()), Encoding.ASCII.GetBytes(k["infoAscii"].GetValue<string>()));
                Check(Convert.ToBase64String(key) == k["productKeyBase64"].GetValue<string>(), k["name"].GetValue<string>());
            }
        });

        foreach (var s in v["sealed"].AsArray())
        {
            await Test("sealed vector opens, and seals to the same bytes: " + s["name"], () =>
            {
                var key = Convert.FromBase64String(s["productKeyBase64"].GetValue<string>());
                var opened = SunLicenseProtection.Open(s["sealed"].GetValue<string>(), key);
                Check(opened.Key.SequenceEqual(Convert.FromBase64String(s["dataBase64"].GetValue<string>())), "data");
                var expected = s["digests"].AsObject().ToDictionary(p => p.Key, p => p.Value.GetValue<string>());
                Check(opened.Value.Count == expected.Count && expected.All(p => opened.Value[p.Key] == p.Value), "digests");
                var nonce = Unhex(s["nonceHex"].GetValue<string>());
                var ct = Gcm.Encrypt(key, nonce, Encoding.UTF8.GetBytes(s["plaintextUtf8"].GetValue<string>()), Encoding.ASCII.GetBytes("SLS1"));
                Check("SLS1." + SunLicenseProtection.EncodeBase64Url(nonce.Concat(ct).ToArray()) == s["sealed"].GetValue<string>(), "seal");
                // the platform's own AES-GCM agrees
                var platform = new byte[ct.Length - 16];
                using var gcm = new AesGcm(key, 16);
                gcm.Decrypt(nonce, ct[..^16], ct[^16..], platform, Encoding.ASCII.GetBytes("SLS1"));
                Check(Encoding.UTF8.GetString(platform) == s["plaintextUtf8"].GetValue<string>(), "platform AES-GCM");
            });
        }

        foreach (var f in v["mustFail"].AsArray())
        {
            await Test("must fail: " + f["name"], () =>
            {
                try
                {
                    SunLicenseProtection.Open(f["sealed"].GetValue<string>(), Convert.FromBase64String(f["productKeyBase64"].GetValue<string>()));
                    throw new Exception("opened");
                }
                catch (SunLicenseLockedException)
                {
                }
            });
        }

        await Test("digests, normalised input, padded base64url", () =>
        {
            foreach (var d in v["digests"].AsArray())
            {
                if (d["inputUtf8"] != null)
                {
                    Check(SunLicenseProtection.Digest(Encoding.UTF8.GetBytes(d["inputUtf8"].GetValue<string>())) == d["sha256Hex"].GetValue<string>(), "utf8");
                }

                if (d["inputBase64"] != null)
                {
                    Check(SunLicenseProtection.Digest(Convert.FromBase64String(d["inputBase64"].GetValue<string>())) == d["sha256Hex"].GetValue<string>(), "b64");
                }

                if (d["input"] != null)
                {
                    Check(SunLicenseProtection.NormaliseDigest(d["input"].GetValue<string>()) == d["normalised"].GetValue<string>(), "normalised");
                }
            }

            var first = v["sealed"][0]["sealed"].GetValue<string>();
            var padded = first + new string('=', (4 - (first.Length - 5) % 4) % 4);
            SunLicenseProtection.Open(padded, Convert.FromBase64String(v["sealed"][0]["productKeyBase64"].GetValue<string>()));
        });

        await Test("locked until a valid answer with unlock; then unseal works and remembers digests", () =>
        {
            var p = Make();
            Check(!p.IsUnlocked, "locked at start");
            try
            {
                p.Unseal(v["sealed"][0]["sealed"].GetValue<string>());
                throw new Exception("unsealed while locked");
            }
            catch (SunLicenseLockedException)
            {
            }

            p.Accept(compat);
            Check(p.IsUnlocked, "unlocked");
            var core = p.Unseal(v["sealed"][0]["sealed"].GetValue<string>());
            Check(core.SequenceEqual(Convert.FromBase64String(v["sealed"][0]["dataBase64"].GetValue<string>())), "core");
            Check(p.Digests["plugin.jar"] == v["sealed"][0]["digests"]["plugin.jar"].GetValue<string>(), "digests");
        });

        await Test("v1 answers work; valid without unlock and unreadable answers keep what it had", () =>
        {
            var p = Make();
            p.Accept(v["wire"]["validateResponseV1"].ToJsonString());
            Check(p.IsUnlocked, "v1");
            foreach (var body in new[] { "{\"valid\":true,\"code\":\"VALID\"}", "<html>502</html>", "{\"status\":401}", null, "" })
            {
                p.Accept(body);
            }

            Check(p.IsUnlocked, "kept");
        });

        await Test("a refused check forgets the unlock, in memory and on disk", () =>
        {
            var dir = TempDir();
            var p = Make(dir);
            p.Accept(compat);
            Check(Directory.GetFiles(dir).Length == 1, "cached");
            p.Accept("{\"valid\":false,\"status\":403,\"code\":\"SUSPENDED\"}");
            Check(!p.IsUnlocked && Directory.GetFiles(dir).Length == 0, "forgotten");
        });

        await Test("the cache unlocks for 7 days on this machine with this key, and nowhere else", () =>
        {
            var dir = TempDir();
            var clock = new Clock();
            Make(dir, clock).Accept(compat);
            var file = Directory.GetFiles(dir).Single();
            var name = Path.GetFileName(file);
            Check(name == ".sunlicense-unlock-" + SunLicenseProtection.Digest(Encoding.UTF8.GetBytes("sunlicense-unlock-file\0" + Key)).Substring(0, 16), name);
            var text = File.ReadAllText(file);
            Check(text.StartsWith("SLC1.") && !text.Contains(unlock), "format");
            Check(Make(dir, clock).IsUnlocked, "same machine");
            Check(!Make(dir, clock, machine: "host-b").IsUnlocked, "another machine");
            Check(!Make(dir, clock, fingerprint: "machine-2").IsUnlocked, "another machine id");
            Check(!Make(dir, clock, licenseKey: "OTHR-XXXX").IsUnlocked, "another key");
            clock.T = T0 + TimeSpan.FromDays(7) - TimeSpan.FromMinutes(1);
            Check(Make(dir, clock).IsUnlocked, "6 days 23:59");
            clock.T = T0 + TimeSpan.FromDays(7);
            Check(!Make(dir, clock).IsUnlocked, "7 days");
            clock.T = T0 - TimeSpan.FromHours(1);
            Check(!Make(dir, clock).IsUnlocked, "clock turned back");

            // the same format as the other SDKs
            var raw = Convert.FromBase64String(text.Substring(5).Replace('-', '+').Replace('_', '/') + new string('=', (4 - (text.Length - 5) % 4) % 4));
            var key = SHA256.HashData(Encoding.UTF8.GetBytes("sunlicense-unlock-cache\0" + Key + "\0machine-1\0host-a"));
            var plain = new byte[raw.Length - 28];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(raw[..12], raw[12..^16], raw[^16..], plain);
            Check(Encoding.UTF8.GetString(plain) == T0.ToUnixTimeMilliseconds() + "\n" + unlock, "plaintext");
        });

        await Test("memory only, and a new license key drops the unlock", () =>
        {
            var p = Make(more: o => o.MemoryOnly = true);
            p.Accept(compat);
            Check(p.IsUnlocked && p.CacheFile() == null, "memory");
            p.License("NEWK-XXXX-XXXX-XXXX", "machine-1");
            Check(!p.IsUnlocked, "new key");
        });

        await Test("integrity: OK, MODIFIED with the changed files, as validate fields; directories too", () =>
        {
            var p = Make();
            p.Accept(compat);
            Check(p.Integrity(_ => new byte[1]) == null, "nothing unsealed yet");
            p.Unseal(v["sealed"][2]["sealed"].GetValue<string>());
            var files = new Dictionary<string, byte[]>
            {
                ["Main.class"] = Encoding.UTF8.GetBytes("main"), ["assets/rules.dat"] = Encoding.UTF8.GetBytes("rules"), ["lib/util.jar"] = Encoding.UTF8.GetBytes("util"),
            };
            Func<string, byte[]> reader = f => files.TryGetValue(f, out var b) ? b : null;
            Check(p.Integrity(reader) == "OK", "ok");
            Check(p.ValidateFields().Count == 1 && p.ValidateFields()["integrity"] == "OK", "fields ok");
            files["lib/util.jar"] = Encoding.UTF8.GetBytes("patched");
            files.Remove("Main.class");
            Check(p.Integrity(reader) == "MODIFIED" && p.IntegrityResult == "MODIFIED", "modified");
            Check(p.ValidateFields()["integrityDetail"] == "2 changed: Main.class (missing), lib/util.jar", p.ValidateFields()["integrityDetail"]);

            var root = TempDir();
            Directory.CreateDirectory(Path.Combine(root, "lib"));
            File.WriteAllText(Path.Combine(root, "Main.class"), "main");
            File.WriteAllText(Path.Combine(root, "lib", "util.jar"), "util");
            var digests = new Dictionary<string, string>
            {
                ["Main.class"] = SunLicenseProtection.Digest(Encoding.UTF8.GetBytes("main")),
                ["lib/util.jar"] = "SHA256:" + SunLicenseProtection.Digest(Encoding.UTF8.GetBytes("util")).ToUpperInvariant(),
                ["../escape"] = "x",
            };
            Check(p.Integrity(root, digests) == "MODIFIED" && p.ValidateFields()["integrityDetail"] == "1 changed: ../escape (missing)", "escape");
            digests.Remove("../escape");
            Check(p.Integrity(root, digests) == "OK", "directory ok");
        });

        await Test("integrity detail stays within 200 characters", () =>
        {
            var d = SunLicenseProtection.Detail(Enumerable.Range(0, 40).Select(i => $"lib/some-long-library-name-{i:00}.jar").ToList());
            Check(d.Length <= 200 && d.StartsWith("40 changed: ") && System.Text.RegularExpressions.Regex.IsMatch(d, @", \+\d+ more$"), d);
        });

        await Test("notice: product, owner, masked key, terms; never the full key", () =>
        {
            var p = Make(more: o => { o.Product = "My Script"; o.Owner = "Example Studio"; o.Terms = "https://example.com/terms"; });
            Check(p.Notice() == "My Script is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://example.com/terms", p.Notice());
            Check(Make().Notice() == "This product is licensed software. License AX8P-XXXX-XXXX-XXXX.", "default");
            Check(SunLicenseProtection.Mask(null) == "(none)" && SunLicenseProtection.Mask("ABCDEFGHIJ") == "ABCDXXXXXX", "mask");
        });

        await Test("protected files: API key, license and machine headers; refusals say why", async () =>
        {
            string url = null;
            IDictionary<string, string> headers = null;
            var status = 200;
            var body = "RULES";
            Func<string, IDictionary<string, string>, Task<KeyValuePair<int, byte[]>>> get = (u, h) =>
            {
                url = u;
                headers = h;
                return Task.FromResult(new KeyValuePair<int, byte[]>(status, Encoding.UTF8.GetBytes(body)));
            };
            var p = Make(more: o => { o.ProductCode = "my script"; o.ApiKey = "sk_test"; o.Get = get; });
            Check(Encoding.UTF8.GetString(await p.ProtectedFileAsync("rules.dat")) == "RULES", "body");
            Check(url == "https://api.example.test/api/v2/protected-files/my%20script/rules.dat", url);
            Check(headers["Authorization"] == "Bearer sk_test" && headers["X-License-Key"] == Key && headers["X-Fingerprint"] == "machine-1", "headers");
            status = 403;
            body = "{\"code\":\"SUSPENDED\"}";
            try
            {
                await p.ProtectedFileAsync("rules.dat");
                throw new Exception("not refused");
            }
            catch (SunLicenseRefusedException e)
            {
                Check(e.Status == 403 && e.Message.Contains("SUSPENDED"), e.Message);
            }

            status = 503;
            try
            {
                await p.ProtectedFileAsync("rules.dat");
                throw new Exception("not an outage");
            }
            catch (SunLicenseException)
            {
            }
        });

        await Test("client.ValidateAsync sends integrity and keeps or forgets the unlock", async () =>
        {
            var handler = new Handler();
            using var http = new HttpClient(handler);
            using var client = new SunLicenseClient(http, "https://api.example.test", "sk_test");
            var p = client.Protection(new SunLicenseProtectionOptions { CacheDirectory = TempDir(), Machine = () => "host-a" });
            Check(p.ApiKey == "sk_test" && p.BaseUrl == "https://api.example.test", "bound");
            handler.Answers.Enqueue((200, compat));
            var r = await client.ValidateAsync(Key, new Dictionary<string, string> { ["fingerprint"] = "machine-1" });
            Check(r.IsValid && p.IsUnlocked && p.LicenseKey == Key && p.Fingerprint == "machine-1", "valid");
            Check(handler.Sent[0]["integrity"] == null, "no integrity before a check");
            p.Unseal(v["sealed"][0]["sealed"].GetValue<string>());
            Check(p.Integrity(_ => Encoding.UTF8.GetBytes("not the jar")) == "MODIFIED", "modified");
            handler.Answers.Enqueue((403, "{\"valid\":false,\"status\":403,\"code\":\"SUSPENDED\"}"));
            r = await client.ValidateAsync(Key, new Dictionary<string, string> { ["fingerprint"] = "machine-1" });
            Check(!r.IsValid, "refused");
            Check(handler.Sent[1]["integrity"].GetValue<string>() == "MODIFIED" && handler.Sent[1]["integrityDetail"].GetValue<string>() == "1 changed: plugin.jar", handler.Sent[1].ToJsonString());
            Check(!p.IsUnlocked, "forgotten");
        });

        return (count, failed);
    }

    sealed class Handler : HttpMessageHandler
    {
        public Queue<(int, string)> Answers { get; } = new();

        public List<JsonNode> Sent { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent.Add(JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken)));
            var (status, body) = Answers.Dequeue();
            return new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body) };
        }
    }
}
