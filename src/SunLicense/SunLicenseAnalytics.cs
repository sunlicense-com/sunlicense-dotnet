using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SunLicense
{
    /// <summary>
    /// Built-in product analytics: every 30 minutes, in the background, this install tells SunLicense its
    /// product version, OS, architecture, CPU cores, locale, .NET runtime and platform (a FiveM or RedM
    /// server, a Discord bot, Unity or standalone). Sellers see the totals on the product's Analytics tab.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It never blocks, delays or fails a license check and never throws: errors are swallowed. Nothing is
    /// sent while the product's <see cref="SunLicenseAnalyticsOptions.Enabled"/> switch is off, the
    /// environment variable <c>SUNLICENSE_ANALYTICS</c> is <c>off</c>/<c>false</c>/<c>0</c>, the runtime
    /// setting <c>sunlicense.analytics</c> (runtimeconfig.json <c>configProperties</c>) is <c>false</c>, or
    /// on FiveM the convar <c>sunlicense_analytics</c> is off; each is checked before every report. No
    /// personal data is sent: no user names, host names, IP addresses, file paths or player names.
    /// </para>
    /// <example>
    /// <code>
    /// // A licensed product: the same API key, license key and machine id it validates with.
    /// using var analytics = client.Analytics(licenseKey, machineId,
    ///     new SunLicenseAnalyticsOptions { ProductVersion = "2.3.1", Enabled = config.Analytics });
    /// // A free product: its public product analytics id (Product → Analytics), no license needed.
    /// using var analytics = SunLicenseAnalytics.ForProduct("pa_7Hk2mQ9xZr4LbN8vT1wYcD");
    /// analytics.Feature("auto-sell");
    /// analytics.SimplePie("storage", () => config.Storage);
    /// </code>
    /// </example>
    /// </remarks>
    public sealed class SunLicenseAnalytics : IDisposable
    {
        /// <summary>Sent as <c>sdk.name</c>; the version is <see cref="SunLicenseClient.Version"/>.</summary>
        public const string SdkName = "csharp";

        /// <summary>The default API base URL.</summary>
        public const string DefaultBaseUrl = "https://api.sunlicense.com";

        /// <summary>The environment variable that switches analytics off on a machine.</summary>
        public const string EnvSwitch = "SUNLICENSE_ANALYTICS";

        internal static readonly TimeSpan Interval = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan MinWait = TimeSpan.FromMinutes(1);
        private static readonly TimeSpan MaxWait = TimeSpan.FromHours(24);
        private const string PathSuffix = "/api/v2/analytics/report";
        private const int MaxBody = 16 * 1024;
        private const string InstallIdFile = ".sunlicense-install-id";
        private const int MaxFeatures = 50, MaxCharts = 30, MaxValues = 50, MaxBar = 20, MaxNumber = 1000000000;
        private static readonly string[] CoreKeys = { "schema", "licenseKey", "fingerprint", "productAnalyticsId", "installId", "sdk", "metrics" };
        private static readonly HashSet<string> Off = new HashSet<string>(StringComparer.Ordinal) { "off", "false", "0", "no", "disabled" };
        private static readonly Regex Id = new Regex("^[a-z0-9][a-z0-9._-]{0,47}$", RegexOptions.CultureInvariant);
        private static readonly Regex InstallIdPattern = new Regex("^[A-Za-z0-9_-]{8,64}$", RegexOptions.CultureInvariant);

        private readonly string _endpoint;
        private readonly string _apiKey;
        private readonly Func<string> _licenseKey;
        private readonly string _fingerprint;
        private readonly string _productAnalyticsId;
        private readonly Func<string> _productVersion;
        private readonly string _platformName;
        private readonly string _platformVersion;
        private readonly Func<bool> _enabled;
        private readonly string _installIdFile;
        private readonly Func<string, string> _env;
        private readonly Func<string, IDictionary<string, string>, string, Task<Answer>> _transport;
        private readonly Random _random;
        private readonly TimeSpan? _firstDelay;
        private readonly Func<IDictionary<string, object>> _collect;
        private readonly object _lock = new object();
        private readonly Dictionary<string, int> _features = new Dictionary<string, int>();
        private readonly List<string> _featureOrder = new List<string>();
        private readonly List<KeyValuePair<string, Chart>> _charts = new List<KeyValuePair<string, Chart>>();
        private HttpClient _http;
        private Timer _timer;
        private volatile bool _closed;
        private IDictionary<string, object> _metrics;
        private string _installId;

        internal struct Answer
        {
            public Answer(int status, string retryAfter)
            {
                Status = status;
                RetryAfter = retryAfter;
            }

            public int Status { get; }

            public string RetryAfter { get; }
        }

        private sealed class Chart
        {
            public string Type;
            public Func<object> Callback;
        }

        private SunLicenseAnalytics(SunLicenseAnalyticsOptions o)
        {
            o = o ?? new SunLicenseAnalyticsOptions();
            var baseUrl = string.IsNullOrWhiteSpace(o.BaseUrl) ? DefaultBaseUrl : o.BaseUrl.Trim();
            _endpoint = baseUrl.TrimEnd('/') + PathSuffix;
            _apiKey = Clean(o.ApiKey, 512);
            _licenseKey = o.LicenseKeyProvider ?? (() => o.LicenseKey);
            _fingerprint = Clean(o.Fingerprint, 255);
            _productAnalyticsId = Clean(o.ProductAnalyticsId, 64);
            _productVersion = o.ProductVersionProvider ?? (() => o.ProductVersion);
            _platformName = o.PlatformName;
            _platformVersion = o.PlatformVersion;
            var enabled = o.Enabled;
            _enabled = o.EnabledProvider ?? (() => enabled);
            var directory = o.DataDirectory;
            if (string.IsNullOrEmpty(directory))
            {
                var home = Safe(() => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                directory = Path.Combine(string.IsNullOrEmpty(home) ? "." : home, ".sunlicense");
            }

            _installIdFile = Path.Combine(directory, InstallIdFile);
            _env = o.Env ?? Environment.GetEnvironmentVariable;
            _transport = o.Transport ?? PostAsync;
            _random = o.Random ?? new Random();
            _firstDelay = o.FirstDelay;
            _collect = o.Collect;
        }

        /// <summary>Starts reporting in the background (first report in 1–30 minutes). Never throws.</summary>
        /// <param name="options">The product's identity and settings.</param>
        /// <returns>The reporter; dispose it when the product shuts down.</returns>
        public static SunLicenseAnalytics Start(SunLicenseAnalyticsOptions options)
        {
            try
            {
                return new SunLicenseAnalytics(options).Begin();
            }
            catch (Exception)
            {
                return new SunLicenseAnalytics(new SunLicenseAnalyticsOptions { Enabled = false });
            }
        }

        /// <summary>A free product: reports with its public product analytics id (Product → Analytics). Never throws.</summary>
        /// <param name="productAnalyticsId">The id, <c>pa_…</c>.</param>
        /// <param name="options">Other settings (product version, switch, data directory…).</param>
        /// <returns>The reporter; dispose it when the product shuts down.</returns>
        public static SunLicenseAnalytics ForProduct(string productAnalyticsId, SunLicenseAnalyticsOptions options = null)
        {
            var o = (options ?? new SunLicenseAnalyticsOptions()).Copy();
            o.ProductAnalyticsId = productAnalyticsId;
            return Start(o);
        }

        /// <summary>A reporter that isn't started: it only sends when you call <see cref="SendNowAsync"/>.</summary>
        /// <param name="options">The product's identity and settings.</param>
        /// <returns>The reporter.</returns>
        public static SunLicenseAnalytics Create(SunLicenseAnalyticsOptions options)
        {
            return new SunLicenseAnalytics(options);
        }

        /// <summary>Gets a value indicating whether reporting is on (the product's switch and the machine's opt-outs).</summary>
        public bool IsEnabled => !OptedOut();

        /// <summary>
        /// Counts uses of one of your product's features ("auto-sell"): <paramref name="uses"/> is added and sent
        /// with the next report, and kept until a report is stored. Cheap, thread-safe, never throws; nothing is
        /// counted while analytics is off. Names are lower-cased and must match <c>[a-z0-9][a-z0-9._-]{0,47}</c>.
        /// </summary>
        /// <param name="name">The feature's name.</param>
        /// <param name="uses">How many uses to add (at least 1).</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics Feature(string name, int uses = 1)
        {
            try
            {
                var id = ChartId(name);
                if (id == null || uses < 1 || OptedOut())
                {
                    return this;
                }

                lock (_lock)
                {
                    if (!_features.TryGetValue(id, out var count))
                    {
                        _featureOrder.Add(id);
                    }

                    _features[id] = (int)Math.Min(MaxNumber, (long)count + uses);
                }
            }
            catch (Exception)
            {
                // never throws
            }

            return this;
        }

        /// <summary>A pie of one value per install, e.g. <c>SimplePie("storage", () => config.Storage)</c>.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics SimplePie(string id, Func<string> callback) => AddChart(id, "simple_pie", callback);

        /// <summary>A pie of weighted values per install.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null or empty leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics AdvancedPie(string id, Func<IDictionary<string, int>> callback) => AddChart(id, "advanced_pie", callback);

        /// <summary>A two-level pie, e.g. database → version.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null or empty leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics DrilldownPie(string id, Func<IDictionary<string, IDictionary<string, int>>> callback) => AddChart(id, "drilldown_pie", callback);

        /// <summary>A number summed over installs, e.g. <c>SingleLine("players", () => players.Count)</c>.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics SingleLine(string id, Func<int?> callback) => AddChart(id, "single_line", callback);

        /// <summary>Several numbers per install, one line each.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null or empty leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics MultiLine(string id, Func<IDictionary<string, int>> callback) => AddChart(id, "multi_line", callback);

        /// <summary>Numbers per category.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null or empty leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics SimpleBar(string id, Func<IDictionary<string, int>> callback) => AddChart(id, "simple_bar", callback);

        /// <summary>Several numbers per category.</summary>
        /// <param name="id">The chart id.</param>
        /// <param name="callback">Called before each report; null or empty leaves the chart out.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics AdvancedBar(string id, Func<IDictionary<string, int[]>> callback) => AddChart(id, "advanced_bar", callback);

        /// <summary>Stops sending a custom chart.</summary>
        /// <param name="id">The chart id.</param>
        /// <returns>This reporter.</returns>
        public SunLicenseAnalytics RemoveChart(string id)
        {
            var key = ChartId(id);
            lock (_lock)
            {
                _charts.RemoveAll(c => c.Key == key);
            }

            return this;
        }

        /// <summary>
        /// Sends one report now and returns the HTTP status (204 = stored, 0 = nothing sent because analytics is
        /// off or the product isn't identified, -1 = no answer). For tests and tools. Never throws.
        /// </summary>
        /// <returns>The HTTP status.</returns>
        public async Task<int> SendNowAsync()
        {
            try
            {
                return (await SendAsync().ConfigureAwait(false)).Status;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>Stops reporting. Call it when the product shuts down.</summary>
        public void Dispose()
        {
            _closed = true;
            lock (_lock)
            {
                _timer?.Dispose();
                _timer = null;
                _http?.Dispose();
                _http = null;
            }
        }

        /// <summary>First report after a random 1–30 minutes, so a fleet restarted together doesn't report together.</summary>
        internal static TimeSpan FirstDelay(Random random) => TimeSpan.FromSeconds(60 + random.Next(29 * 60 + 1));

        /// <summary>30 minutes after a 204 or no answer; else the server's Retry-After, between 1 minute and 24 hours.</summary>
        internal static TimeSpan NextDelay(int status, string retryAfter)
        {
            if (status == 204 || retryAfter == null
                || !long.TryParse(retryAfter.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return Interval;
            }

            var delay = TimeSpan.FromSeconds(Math.Min(seconds, (long)MaxWait.TotalSeconds));
            return delay < MinWait ? MinWait : delay;
        }

        internal static string ChartId(string value)
        {
            if (value == null)
            {
                return null;
            }

            var id = value.Trim().ToLowerInvariant();
            return Id.IsMatch(id) ? id : null;
        }

        /// <summary>Trimmed, control characters removed, cut at <paramref name="max"/>; null when empty.</summary>
        internal static string Clean(string value, int max)
        {
            if (value == null)
            {
                return null;
            }

            var b = new StringBuilder(value.Length);
            foreach (var c in value)
            {
                if (!char.IsControl(c))
                {
                    b.Append(c);
                }
            }

            var s = b.ToString().Trim();
            if (s.Length > max)
            {
                s = s.Substring(0, char.IsHighSurrogate(s[max - 1]) ? max - 1 : max).Trim();
            }

            return s.Length == 0 ? null : s;
        }

        internal static bool IsOff(string value) => value != null && Off.Contains(value.Trim().ToLowerInvariant());

        /// <summary>Raw values; the server maps them to families and majors.</summary>
        internal static IDictionary<string, object> CollectMetrics(string platformName, string platformVersion)
        {
            var m = new Dictionary<string, object>();
            var version = Safe(() => Environment.OSVersion.Version);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Put(m, "os", version != null && version.Major == 10 ? (version.Build >= 22000 ? "Windows 11" : "Windows 10") : "Windows");
                Put(m, "osVersion", version?.ToString());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Put(m, "os", "Mac OS X");
                Put(m, "osVersion", MacProductVersion() ?? version?.ToString());
            }
            else
            {
                // "Linux 5.15.0-1051-oracle #57~20.04.1-Ubuntu SMP …", "FreeBSD 14.0-RELEASE …"
                var parts = (Safe(() => RuntimeInformation.OSDescription) ?? string.Empty).Split(' ');
                Put(m, "os", parts.Length > 0 ? parts[0] : null);
                Put(m, "osVersion", parts.Length > 1 ? parts[1] : null);
            }

            Put(m, "arch", Safe(() => RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()));
            m["cores"] = Math.Max(1, Math.Min(1024, Environment.ProcessorCount));
            Put(m, "locale", Safe(() => CultureInfo.CurrentCulture.Name));
            var framework = Safe(() => RuntimeInformation.FrameworkDescription) ?? string.Empty;
            m["runtime"] = framework.StartsWith("Mono", StringComparison.OrdinalIgnoreCase) ? "mono" : "dotnet";
            var number = Regex.Match(framework, @"\d+(\.\d+)*");
            Put(m, "runtimeVersion", number.Success ? number.Value : null);
            if (platformName == null)
            {
                var detected = DetectPlatform();
                platformName = detected.Key;
                platformVersion = detected.Value;
            }

            Put(m, "platform", Clean(platformName.ToLowerInvariant(), 32));
            Put(m, "platformVersion", platformVersion);
            return m;
        }

        /// <summary>What the product runs on, from the loaded assemblies: FiveM/RedM, a Discord bot, Unity, else standalone.</summary>
        internal static KeyValuePair<string, string> DetectPlatform()
        {
            try
            {
                var names = AppDomain.CurrentDomain.GetAssemblies().Select(a => a.GetName()).ToList();
                if (names.Any(n => n.Name == "CitizenFX.Core" || n.Name == "CitizenFX.Core.Server"))
                {
                    var version = Convar("version", string.Empty) ?? string.Empty;
                    var build = Regex.Match(version, @"v\d+\.\d+\.\d+\.(\d+)");
                    var name = Convar("gamename", "gta5") == "rdr3" ? "redm" : "fivem";
                    return new KeyValuePair<string, string>(name, build.Success ? build.Groups[1].Value : null);
                }

                var discord = names.FirstOrDefault(n => n.Name == "Discord.Net.WebSocket" || n.Name == "Discord.Net.Core"
                    || n.Name == "DSharpPlus" || n.Name == "NetCord" || n.Name == "Remora.Discord.API");
                if (discord != null)
                {
                    return new KeyValuePair<string, string>("discord", discord.Version?.ToString(3));
                }

                if (names.Any(n => n.Name == "UnityEngine.CoreModule" || n.Name == "UnityEngine"))
                {
                    var application = Type.GetType("UnityEngine.Application, UnityEngine.CoreModule")
                        ?? Type.GetType("UnityEngine.Application, UnityEngine");
                    var unityVersion = application?.GetProperty("unityVersion", BindingFlags.Public | BindingFlags.Static)?.GetValue(null) as string;
                    return new KeyValuePair<string, string>("unity", unityVersion);
                }
            }
            catch (Exception)
            {
                // fall through
            }

            return new KeyValuePair<string, string>("standalone", null);
        }

        private static readonly Lazy<MethodInfo> GetConvar = new Lazy<MethodInfo>(() =>
        {
            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                var method = Safe(() => assembly.GetType("CitizenFX.Core.Native.API", false)?.GetMethod("GetConvar", new[] { typeof(string), typeof(string) }));
                if (method != null)
                {
                    return method;
                }
            }

            return null;
        });

        /// <summary>A FiveM convar through CitizenFX's API, by reflection (no reference to CitizenFX); null elsewhere.</summary>
        private static string Convar(string name, string fallback)
        {
            try
            {
                return GetConvar.Value?.Invoke(null, new object[] { name, fallback }) as string;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string MacProductVersion()
        {
            var plist = Safe(() => File.ReadAllText("/System/Library/CoreServices/SystemVersion.plist"));
            var match = plist == null ? null : Regex.Match(plist, @"<key>ProductVersion</key>\s*<string>([^<]+)</string>");
            return match != null && match.Success ? match.Groups[1].Value : null;
        }

        internal static object ChartData(string type, object value)
        {
            if (value == null)
            {
                return null;
            }

            switch (type)
            {
                case "simple_pie":
                    var s = Clean(value as string, 64);
                    return s == null ? null : new Dictionary<string, object> { ["value"] = s };
                case "single_line":
                    var n = value as int?;
                    return n.HasValue && Math.Abs((long)n.Value) <= MaxNumber ? new Dictionary<string, object> { ["value"] = n.Value } : null;
                case "advanced_pie":
                case "multi_line":
                case "simple_bar":
                    var values = Numbers(value as IDictionary<string, int>, type == "advanced_pie" ? 1 : -MaxNumber);
                    return values == null ? null : new Dictionary<string, object> { ["values"] = values };
                case "drilldown_pie":
                    var outer = new Dictionary<string, object>();
                    foreach (var pair in (value as IDictionary<string, IDictionary<string, int>>) ?? new Dictionary<string, IDictionary<string, int>>())
                    {
                        var key = Clean(pair.Key, 64);
                        var slice = Numbers(pair.Value, 1);
                        if (key != null && slice != null && outer.Count < MaxValues)
                        {
                            outer[key] = slice;
                        }
                    }

                    return outer.Count == 0 ? null : new Dictionary<string, object> { ["values"] = outer };
                case "advanced_bar":
                    var bars = new Dictionary<string, object>();
                    foreach (var pair in (value as IDictionary<string, int[]>) ?? new Dictionary<string, int[]>())
                    {
                        var key = Clean(pair.Key, 64);
                        var nums = (pair.Value ?? new int[0]).Take(MaxBar).ToList();
                        if (key != null && nums.Count > 0 && nums.All(x => Math.Abs((long)x) <= MaxNumber) && bars.Count < MaxValues)
                        {
                            bars[key] = nums.Cast<object>().ToList();
                        }
                    }

                    return bars.Count == 0 ? null : new Dictionary<string, object> { ["values"] = bars };
                default:
                    return null;
            }
        }

        private static Dictionary<string, object> Numbers(IDictionary<string, int> map, int min)
        {
            var output = new Dictionary<string, object>();
            foreach (var pair in map ?? new Dictionary<string, int>())
            {
                var key = Clean(pair.Key, 64);
                if (key != null && pair.Value >= min && Math.Abs((long)pair.Value) <= MaxNumber && output.Count < MaxValues)
                {
                    output[key] = pair.Value;
                }
            }

            return output.Count == 0 ? null : output;
        }

        private SunLicenseAnalytics AddChart<T>(string id, string type, Func<T> callback)
        {
            var key = ChartId(id);
            if (key == null || callback == null)
            {
                return this;
            }

            lock (_lock)
            {
                _charts.RemoveAll(c => c.Key == key); // the same id replaces the earlier one, at the end
                _charts.Add(new KeyValuePair<string, Chart>(key, new Chart { Type = type, Callback = () => callback() }));
            }

            return this;
        }

        private SunLicenseAnalytics Begin()
        {
            if (_productAnalyticsId == null && (_apiKey == null || _fingerprint == null))
            {
                return this; // no product analytics id, and no API key and machine id: not reporting
            }

            lock (_lock)
            {
                _timer = new Timer(_ => Tick(), null, Timeout.Infinite, Timeout.Infinite);
            }

            Schedule(_firstDelay ?? FirstDelay(_random));
            return this;
        }

        private void Schedule(TimeSpan delay)
        {
            lock (_lock)
            {
                if (!_closed)
                {
                    try
                    {
                        _timer?.Change(delay, Timeout.InfiniteTimeSpan);
                    }
                    catch (ObjectDisposedException)
                    {
                        // closed meanwhile
                    }
                }
            }
        }

        private async void Tick()
        {
            var next = Interval;
            try
            {
                var answer = await SendAsync().ConfigureAwait(false);
                next = NextDelay(answer.Status, answer.RetryAfter);
            }
            catch (Exception)
            {
                // a report never takes the product down
            }
            finally
            {
                Schedule(next);
            }
        }

        private bool OptedOut()
        {
            try
            {
                if (IsOff(_env(EnvSwitch)) || IsOff(AppContext.GetData("sunlicense.analytics")?.ToString()))
                {
                    return true;
                }

                if (Convar("sunlicense_analytics", "on") is string convar && IsOff(convar))
                {
                    return true;
                }

                return !_enabled();
            }
            catch (Exception)
            {
                return true; // a switch that can't be read counts as off
            }
        }

        private async Task<Answer> SendAsync()
        {
            if (_closed)
            {
                return new Answer(0, null);
            }

            if (OptedOut())
            {
                return new Answer(0, null);
            }

            var report = Report(out var sending);
            if (report == null)
            {
                return new Answer(0, null);
            }

            var body = Json(report);
            if (Encoding.UTF8.GetByteCount(body) > MaxBody)
            {
                foreach (var key in report.Keys.Where(k => !CoreKeys.Contains(k)).ToList())
                {
                    report.Remove(key);
                }

                sending = null;
                body = Json(report);
            }

            var headers = new Dictionary<string, string>
            {
                ["User-Agent"] = "sunlicense-dotnet/" + SunLicenseClient.Version + " analytics",
            };
            if (report.ContainsKey("licenseKey"))
            {
                headers["Authorization"] = "Bearer " + _apiKey;
            }

            Answer answer;
            try
            {
                answer = await _transport(_endpoint, headers, body).ConfigureAwait(false);
            }
            catch (Exception)
            {
                answer = new Answer(-1, null);
            }

            if (answer.Status == 204 && sending != null)
            {
                lock (_lock)
                {
                    foreach (var pair in sending)
                    {
                        var left = (_features.TryGetValue(pair.Key, out var count) ? count : 0) - pair.Value;
                        if (left > 0)
                        {
                            _features[pair.Key] = left;
                        }
                        else
                        {
                            _features.Remove(pair.Key);
                            _featureOrder.Remove(pair.Key);
                        }
                    }
                }
            }

            return answer;
        }

        /// <summary>The report body, or null when this install can't say who it is yet.</summary>
        private Dictionary<string, object> Report(out Dictionary<string, int> sending)
        {
            sending = null;
            var key = Clean(Safe(_licenseKey), 128);
            var licensed = key != null && _apiKey != null && _fingerprint != null;
            if (!licensed && _productAnalyticsId == null)
            {
                return null;
            }

            var r = new Dictionary<string, object> { ["schema"] = 1 };
            if (licensed)
            {
                r["licenseKey"] = key;
                r["fingerprint"] = _fingerprint;
            }

            if (_productAnalyticsId != null)
            {
                r["productAnalyticsId"] = _productAnalyticsId;
                r["installId"] = InstallId(); // also with a license: an unknown key then still counts
            }

            r["sdk"] = new Dictionary<string, object> { ["name"] = SdkName, ["version"] = SunLicenseClient.Version };
            var metrics = new Dictionary<string, object>();
            Put(metrics, "productVersion", Clean(Safe(_productVersion), 64));
            try
            {
                if (_metrics == null)
                {
                    _metrics = _collect != null ? _collect() : CollectMetrics(_platformName, _platformVersion);
                }

                foreach (var pair in _metrics)
                {
                    metrics[pair.Key] = pair.Value;
                }
            }
            catch (Exception)
            {
                // the identity still goes
            }

            r["metrics"] = metrics;
            List<KeyValuePair<string, Chart>> charts;
            lock (_lock)
            {
                if (_featureOrder.Count > 0)
                {
                    sending = _featureOrder.Take(MaxFeatures).ToDictionary(n => n, n => _features[n]);
                    r["features"] = sending.ToDictionary(p => p.Key, p => (object)p.Value);
                }

                charts = _charts.ToList();
            }

            var list = new List<object>();
            foreach (var chart in charts)
            {
                if (list.Count >= MaxCharts)
                {
                    break;
                }

                object data;
                try
                {
                    data = ChartData(chart.Value.Type, chart.Value.Callback());
                }
                catch (Exception)
                {
                    data = null; // a callback that throws leaves its chart out
                }

                if (data != null)
                {
                    list.Add(new Dictionary<string, object> { ["id"] = chart.Key, ["type"] = chart.Value.Type, ["data"] = data });
                }
            }

            if (list.Count > 0)
            {
                r["charts"] = list;
            }

            return r;
        }

        private string InstallId()
        {
            lock (_lock)
            {
                if (_installId != null)
                {
                    return _installId;
                }

                try
                {
                    if (File.Exists(_installIdFile))
                    {
                        var stored = File.ReadAllText(_installIdFile).Trim();
                        if (InstallIdPattern.IsMatch(stored))
                        {
                            return _installId = stored;
                        }
                    }
                }
                catch (Exception)
                {
                    // unreadable: make a new one
                }

                _installId = Guid.NewGuid().ToString();
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_installIdFile)));
                    File.WriteAllText(_installIdFile, _installId);
                }
                catch (Exception)
                {
                    // read-only disk: this run still has an id
                }

                return _installId;
            }
        }

        private async Task<Answer> PostAsync(string url, IDictionary<string, string> headers, string body)
        {
            HttpClient http;
            lock (_lock)
            {
                if (_closed)
                {
                    return new Answer(0, null);
                }

                http = _http ?? (_http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) });
            }

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                foreach (var header in headers)
                {
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                try
                {
                    using (var response = await http.SendAsync(request).ConfigureAwait(false))
                    {
                        string retryAfter = null;
                        if (response.Headers.TryGetValues("Retry-After", out var values))
                        {
                            retryAfter = values.FirstOrDefault();
                        }

                        return new Answer((int)response.StatusCode, retryAfter);
                    }
                }
                catch (Exception)
                {
                    return new Answer(-1, null);
                }
            }
        }

        private static T Safe<T>(Func<T> get)
        {
            try
            {
                return get();
            }
            catch (Exception)
            {
                return default(T);
            }
        }

        private static void Put(IDictionary<string, object> m, string key, string value)
        {
            var clean = Clean(value, 64);
            if (clean != null)
            {
                m[key] = clean;
            }
        }

        internal static string Json(object value)
        {
            var b = new StringBuilder(512);
            Write(b, value);
            return b.ToString();
        }

        private static void Write(StringBuilder b, object v)
        {
            switch (v)
            {
                case null:
                    b.Append("null");
                    break;
                case bool flag:
                    b.Append(flag ? "true" : "false");
                    break;
                case int i:
                    b.Append(i.ToString(CultureInfo.InvariantCulture));
                    break;
                case long l:
                    b.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;
                case string s:
                    Quote(b, s);
                    break;
                case IDictionary<string, object> map:
                    b.Append('{');
                    var first = true;
                    foreach (var pair in map)
                    {
                        if (!first)
                        {
                            b.Append(',');
                        }

                        first = false;
                        Quote(b, pair.Key);
                        b.Append(':');
                        Write(b, pair.Value);
                    }

                    b.Append('}');
                    break;
                case System.Collections.IEnumerable list:
                    b.Append('[');
                    var firstItem = true;
                    foreach (var item in list)
                    {
                        if (!firstItem)
                        {
                            b.Append(',');
                        }

                        firstItem = false;
                        Write(b, item);
                    }

                    b.Append(']');
                    break;
                default:
                    Quote(b, Convert.ToString(v, CultureInfo.InvariantCulture));
                    break;
            }
        }

        private static void Quote(StringBuilder b, string s)
        {
            b.Append('"');
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': b.Append("\\\""); break;
                    case '\\': b.Append("\\\\"); break;
                    case '\n': b.Append("\\n"); break;
                    case '\r': b.Append("\\r"); break;
                    case '\t': b.Append("\\t"); break;
                    default:
                        if (c < 0x20 || c == '\u2028' || c == '\u2029')
                        {
                            b.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            b.Append(c);
                        }

                        break;
                }
            }

            b.Append('"');
        }
    }

    /// <summary>Settings for <see cref="SunLicenseAnalytics"/>.</summary>
    public sealed class SunLicenseAnalyticsOptions
    {
        /// <summary>Gets or sets the API base URL. Defaults to https://api.sunlicense.com.</summary>
        public string BaseUrl { get; set; }

        /// <summary>Gets or sets the API key the product validates with (licensed products, <c>slk_…</c>).</summary>
        public string ApiKey { get; set; }

        /// <summary>Gets or sets the license key it validates (licensed products).</summary>
        public string LicenseKey { get; set; }

        /// <summary>Gets or sets a function that returns the license key, read before each report (overrides <see cref="LicenseKey"/>).</summary>
        public Func<string> LicenseKeyProvider { get; set; }

        /// <summary>Gets or sets the machine id it validates with (licensed products; <c>host</c>).</summary>
        public string Fingerprint { get; set; }

        /// <summary>Gets or sets the product's public analytics id (<c>pa_…</c>): all a free product needs.</summary>
        public string ProductAnalyticsId { get; set; }

        /// <summary>Gets or sets where the random install id is kept (file .sunlicense-install-id). Defaults to ~/.sunlicense.</summary>
        public string DataDirectory { get; set; }

        /// <summary>Gets or sets the product's version.</summary>
        public string ProductVersion { get; set; }

        /// <summary>Gets or sets a function that returns the product's version (overrides <see cref="ProductVersion"/>).</summary>
        public Func<string> ProductVersionProvider { get; set; }

        /// <summary>Gets or sets a platform name overriding the detected one (e.g. "myengine").</summary>
        public string PlatformName { get; set; }

        /// <summary>Gets or sets the overriding platform's version.</summary>
        public string PlatformVersion { get; set; }

        /// <summary>Gets or sets a value indicating whether the product's own switch is on (its config's <c>analytics: false</c>). Default true.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Gets or sets the product's switch as a function, read before each report (overrides <see cref="Enabled"/>).</summary>
        public Func<bool> EnabledProvider { get; set; }

        internal Func<string, string> Env { get; set; }

        internal Func<string, IDictionary<string, string>, string, Task<SunLicenseAnalytics.Answer>> Transport { get; set; }

        internal Random Random { get; set; }

        internal TimeSpan? FirstDelay { get; set; }

        internal Func<IDictionary<string, object>> Collect { get; set; }

        internal SunLicenseAnalyticsOptions Copy() => (SunLicenseAnalyticsOptions)MemberwiseClone();
    }
}
