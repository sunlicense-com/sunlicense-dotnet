using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SunLicense
{
    /// <summary>
    /// Protection for a licensed product: core unlock, tamper reports, the ownership notice and protected files. The
    /// same behaviour as the Java SDK's <c>SunLicenseProtection</c>.
    /// </summary>
    /// <remarks>
    /// <code>
    /// using var client = new SunLicenseClient("https://api.sunlicense.com", apiKey);
    /// var protection = client.Protection(new SunLicenseProtectionOptions
    /// {
    ///     LicenseKey = key, Fingerprint = machineId,
    ///     Product = "My Script", Owner = "Example Studio", Terms = "https://example.com/terms",
    ///     ProductCode = "my-script",              // for protected files
    ///     CacheDirectory = dataFolder,            // where the 7-day unlock cache lives
    /// });
    /// Console.WriteLine(protection.Notice());     // one line: product, owner, masked key
    /// await client.ValidateAsync(key, new Dictionary&lt;string, string&gt; { ["fingerprint"] = machineId });
    /// byte[] core = protection.Unseal(SealedCore); // throws SunLicenseLockedException without a valid unlock
    /// protection.Integrity(AppContext.BaseDirectory); // "OK" / "MODIFIED", sent with the next check
    /// byte[] rules = await protection.ProtectedFileAsync("rules.dat"); // Standard plan
    /// </code>
    /// <para>
    /// Core unlock: <c>sunlicense seal</c> encrypts part of the product (its "core") under a key only SunLicense holds. A
    /// valid license check answers with that key (<c>unlock</c>); a rejected one (suspended, expired, revoked...)
    /// doesn't, and the unlock this install had is forgotten. So a copy whose license check was cut out can't run its
    /// core. To keep working through outages the unlock from the last valid check is cached on disk for 7 days,
    /// encrypted with a key derived from the license key, the machine id and this machine.
    /// </para>
    /// <para>
    /// Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then
    /// fails its integrity check and is reported. Protection raises the cost and makes leaks visible.
    /// </para>
    /// </remarks>
    public sealed class SunLicenseProtection
    {
        /// <summary>The default API address.</summary>
        public const string DefaultBaseUrl = "https://api.sunlicense.com";

        /// <summary>How long the unlock from the last valid check keeps working without an answer from SunLicense.</summary>
        public static readonly TimeSpan CacheTtl = TimeSpan.FromDays(7);

        private static readonly TimeSpan Skew = TimeSpan.FromMinutes(10);
        private const string SealedPrefix = "SLS1.";
        private const string CachePrefix = "SLC1.";
        private const string CacheFileName = ".sunlicense-unlock-";
        private const int MaxDetail = 200;
        private static readonly byte[] SealedAad = Encoding.ASCII.GetBytes("SLS1");
        private static readonly HttpClient SharedHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };

        private readonly string _baseUrl;
        private readonly string _apiKey;
        private readonly string _productCode;
        private readonly string _productName;
        private readonly string _owner;
        private readonly string _terms;
        private readonly string _cacheDirectory;
        private readonly Func<DateTimeOffset> _now;
        private readonly Func<string> _machine;
        private readonly Func<string, IDictionary<string, string>, Task<KeyValuePair<int, byte[]>>> _get;
        private readonly object _lock = new object();

        private volatile string _licenseKey;
        private volatile string _fingerprint;
        private byte[] _unlock;
        private IReadOnlyDictionary<string, string> _digests = new Dictionary<string, string>();
        private string _integrity;
        private string _integrityDetail;

        /// <summary>Creates the protection helper.</summary>
        public SunLicenseProtection(SunLicenseProtectionOptions options = null)
        {
            var o = options ?? new SunLicenseProtectionOptions();
            _baseUrl = (string.IsNullOrWhiteSpace(o.BaseUrl) ? DefaultBaseUrl : o.BaseUrl).TrimEnd('/');
            _apiKey = Trim(o.ApiKey);
            _licenseKey = Trim(o.LicenseKey);
            _fingerprint = Trim(o.Fingerprint);
            _productCode = Trim(o.ProductCode);
            _productName = Trim(o.Product);
            _owner = Trim(o.Owner);
            _terms = Trim(o.Terms);
            _cacheDirectory = o.MemoryOnly ? null : (Trim(o.CacheDirectory) ?? DefaultCacheDirectory());
            _now = o.Now ?? (() => DateTimeOffset.UtcNow);
            _machine = o.Machine ?? MachineId;
            _get = o.Get;
        }

        /// <summary>The license key this install checks with.</summary>
        public string LicenseKey => _licenseKey;

        /// <summary>The machine id this install checks with.</summary>
        public string Fingerprint => _fingerprint;

        internal string ApiKey => _apiKey;

        internal string BaseUrl => _baseUrl;

        // ---- license and answers ----

        /// <summary>The license key and machine id this install checks with; a different key drops the unlock held in memory.</summary>
        public void License(string licenseKey, string fingerprint)
        {
            var key = Trim(licenseKey);
            lock (_lock)
            {
                if (key == null || key != _licenseKey)
                {
                    _unlock = null;
                }

                _licenseKey = key;
                _fingerprint = Trim(fingerprint);
            }
        }

        /// <summary>
        /// Reads a license check's answer (the JSON body of <c>/api/v2/license/validate</c> or <c>/api/v1/validate</c>). A
        /// valid answer with <c>unlock</c> keeps and caches it; a definite "no" (<c>"valid": false</c>) forgets it.
        /// Anything unreadable is ignored (treat that like no answer). Never throws.
        /// </summary>
        public void Accept(string responseBody)
        {
            if (!(MiniJson.TryParse(responseBody) is IDictionary<string, object> body) || !body.TryGetValue("valid", out var valid))
            {
                return;
            }

            if (valid is bool v)
            {
                Accept(v, v && body.TryGetValue("unlock", out var u) ? u as string : null);
            }
        }

        /// <summary>Same as <see cref="Accept(string)"/> for an answer already read: valid with its unlock (or null), or rejected.</summary>
        public void Accept(bool valid, string unlockBase64)
        {
            if (!valid)
            {
                Rejected();
                return;
            }

            if (string.IsNullOrWhiteSpace(unlockBase64))
            {
                return; // valid, but the product has nothing sealed: keep what we have
            }

            byte[] key;
            try
            {
                key = Convert.FromBase64String(unlockBase64.Trim());
            }
            catch (FormatException)
            {
                return;
            }

            if (!ValidKey(key))
            {
                return;
            }

            lock (_lock)
            {
                _unlock = key;
            }

            WriteCache(key);
        }

        /// <summary>SunLicense said no: the unlock (in memory and on disk) is gone until the next valid check.</summary>
        public void Rejected()
        {
            lock (_lock)
            {
                _unlock = null;
            }

            var file = CacheFile();
            if (file != null)
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception)
                {
                    // nothing to forget
                }
            }
        }

        /// <summary>True when an unlock is available: from this run's valid check or the cache (at most 7 days old).</summary>
        public bool IsUnlocked => Key() != null;

        // ---- core unlock ----

        /// <summary>
        /// Decrypts data sealed with <c>sunlicense seal</c> (an <c>SLS1.</c> string). Throws
        /// <see cref="SunLicenseLockedException"/> without an unlock, or when the data was sealed for another product.
        /// Remembers the digests sealed with it for <see cref="Integrity(Func{string, byte[]}, IDictionary{string, string})"/>.
        /// </summary>
        public byte[] Unseal(string sealedText)
        {
            var key = Key();
            if (key == null)
            {
                throw new SunLicenseLockedException("No valid license check yet: the protected part of this product stays locked.");
            }

            var opened = Open(sealedText, key);
            _digests = opened.Value;
            return opened.Key;
        }

        /// <summary>The digests sealed with the last data <see cref="Unseal"/> opened (path → lowercase hex SHA-256).</summary>
        public IReadOnlyDictionary<string, string> Digests => _digests;

        /// <summary>Opens an <c>SLS1.</c> blob with a product key: the data and its digests.</summary>
        /// <exception cref="SunLicenseLockedException">Wrong key, changed data, or not sealed data.</exception>
        public static KeyValuePair<byte[], IReadOnlyDictionary<string, string>> Open(string sealedText, byte[] key)
        {
            var s = Trim(sealedText);
            if (s == null || !s.StartsWith(SealedPrefix, StringComparison.Ordinal))
            {
                throw new SunLicenseLockedException("Not sealed data: expected text starting with " + SealedPrefix);
            }

            byte[] raw;
            try
            {
                raw = DecodeBase64(s.Substring(SealedPrefix.Length));
            }
            catch (FormatException)
            {
                throw new SunLicenseLockedException("Not sealed data: not base64url");
            }

            if (raw.Length < 12 + 16)
            {
                throw new SunLicenseLockedException("Not sealed data: too short");
            }

            var plain = Gcm.Decrypt(key, Slice(raw, 0, 12), Slice(raw, 12, raw.Length - 12), SealedAad);
            if (plain == null)
            {
                throw new SunLicenseLockedException("This data wasn't sealed for this product's unlock (sealed for another product, or re-sealed since).");
            }

            if (!(MiniJson.TryParse(Encoding.UTF8.GetString(plain)) is IDictionary<string, object> m) || !(m.TryGetValue("data", out var d) && d is string data))
            {
                throw new SunLicenseLockedException("Not sealed data: sealed content has no data");
            }

            var digests = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (m.TryGetValue("digests", out var dg) && dg is IDictionary<string, object> map)
            {
                foreach (var pair in map)
                {
                    if (pair.Value is string hex)
                    {
                        digests[pair.Key] = hex.ToLowerInvariant();
                    }
                }
            }

            return new KeyValuePair<byte[], IReadOnlyDictionary<string, string>>(DecodeBase64(data), new Dictionary<string, string>(digests));
        }

        /// <summary>
        /// Compares <paramref name="digests"/> (path → hex SHA-256; default: the ones sealed with the last
        /// <see cref="Unseal"/>) with what <paramref name="reader"/> returns for each path (null = missing). Returns
        /// <c>"OK"</c> or <c>"MODIFIED"</c>, or null when nothing was sealed with digests; the result goes with the next
        /// license check (<see cref="ValidateFields"/>).
        /// </summary>
        public string Integrity(Func<string, byte[]> reader, IDictionary<string, string> digests = null)
        {
            var expected = digests != null ? new Dictionary<string, string>(digests) : _digests.ToDictionary(p => p.Key, p => p.Value);
            if (expected.Count == 0)
            {
                return null;
            }

            var changed = new List<string>();
            foreach (var path in expected.Keys.OrderBy(k => k, StringComparer.Ordinal))
            {
                byte[] bytes;
                try
                {
                    bytes = reader(path);
                }
                catch (Exception)
                {
                    bytes = null;
                }

                if (bytes == null)
                {
                    changed.Add(path + " (missing)");
                }
                else if (Digest(bytes) != NormaliseDigest(expected[path]))
                {
                    changed.Add(path);
                }
            }

            lock (_lock)
            {
                _integrity = changed.Count == 0 ? "OK" : "MODIFIED";
                _integrityDetail = changed.Count == 0 ? null : Detail(changed);
                return _integrity;
            }
        }

        /// <summary><see cref="Integrity(Func{string, byte[]}, IDictionary{string, string})"/> over the files of a directory (e.g. <c>AppContext.BaseDirectory</c>).</summary>
        public string Integrity(string directory, IDictionary<string, string> digests = null)
        {
            var root = Path.GetFullPath(directory ?? Directory.GetCurrentDirectory());
            var prefix = root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) ? root : root + Path.DirectorySeparatorChar;
            return Integrity(name =>
            {
                var p = Path.GetFullPath(Path.Combine(root, name.Replace('/', Path.DirectorySeparatorChar)));
                return p.StartsWith(prefix, StringComparison.Ordinal) && File.Exists(p) ? File.ReadAllBytes(p) : null;
            }, digests);
        }

        /// <summary>The latest integrity result, or null before any.</summary>
        public string IntegrityResult => _integrity;

        /// <summary>
        /// Fields to add to the next license check's JSON body: <c>integrity</c> and, when modified,
        /// <c>integrityDetail</c>. Empty before any integrity check. Works as <c>ValidateAsync</c>'s context too.
        /// </summary>
        public IDictionary<string, string> ValidateFields()
        {
            var fields = new Dictionary<string, string>();
            lock (_lock)
            {
                if (_integrity != null)
                {
                    fields["integrity"] = _integrity;
                    if (_integrityDetail != null)
                    {
                        fields["integrityDetail"] = _integrityDetail;
                    }
                }
            }

            return fields;
        }

        // ---- ownership notice ----

        /// <summary>
        /// One line for the start-up log: product, owner, masked license key and terms link, e.g. "My Script is licensed
        /// software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://…". Never the full key or the buyer's name.
        /// </summary>
        public string Notice()
        {
            var b = new StringBuilder(_productName ?? "This product").Append(" is licensed software");
            if (_owner != null)
            {
                b.Append(" by ").Append(_owner);
            }

            b.Append(". License ").Append(Mask(_licenseKey)).Append('.');
            if (_terms != null)
            {
                b.Append(" Terms: ").Append(_terms);
            }

            return b.ToString();
        }

        /// <summary>"AX8P-XXXX-XXXX-XXXX": the first group, the rest as X.</summary>
        public static string Mask(string key)
        {
            var k = Trim(key);
            if (k == null)
            {
                return "(none)";
            }

            var groups = k.Split('-');
            if (groups.Length == 1)
            {
                return k.Substring(0, Math.Min(4, k.Length)) + new string('X', Math.Max(0, k.Length - 4));
            }

            return string.Join("-", new[] { groups[0] }.Concat(groups.Skip(1).Select(g => new string('X', g.Length))));
        }

        // ---- protected files ----

        /// <summary>
        /// Downloads a protected file uploaded to the product (Standard plan). SunLicense sends it only while the license
        /// is valid. Throws <see cref="SunLicenseRefusedException"/> when it says no, <see cref="SunLicenseException"/>
        /// when it can't be reached.
        /// </summary>
        public async Task<byte[]> ProtectedFileAsync(string name, CancellationToken cancellationToken = default)
        {
            if (_productCode == null)
            {
                throw new InvalidOperationException("Set ProductCode to download protected files");
            }

            if (_licenseKey == null)
            {
                throw new SunLicenseRefusedException(401, "No license key");
            }

            var url = _baseUrl + "/api/v2/protected-files/" + Uri.EscapeDataString(_productCode) + "/" + Uri.EscapeDataString(name);
            var headers = new Dictionary<string, string> { ["X-License-Key"] = _licenseKey };
            if (_apiKey != null)
            {
                headers["Authorization"] = "Bearer " + _apiKey;
            }

            if (_fingerprint != null)
            {
                headers["X-Fingerprint"] = _fingerprint;
            }

            KeyValuePair<int, byte[]> answer;
            try
            {
                answer = await (_get ?? HttpGet)(url, headers).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException || e is TaskCanceledException)
            {
                throw new SunLicenseException("Cannot reach SunLicense at " + _baseUrl, e);
            }

            var status = answer.Key;
            if (status == 200)
            {
                return answer.Value;
            }

            if (status >= 500 || status == 429)
            {
                throw new SunLicenseException("SunLicense returned HTTP " + status + " for protected file " + name, null);
            }

            string code = null;
            if (MiniJson.TryParse(Encoding.UTF8.GetString(answer.Value ?? new byte[0])) is IDictionary<string, object> body)
            {
                code = (body.TryGetValue("code", out var c) ? c as string : null) ?? (body.TryGetValue("detail", out var d) ? d as string : null);
            }

            throw new SunLicenseRefusedException(status, "SunLicense refused protected file " + name + " (HTTP " + status + (code != null ? ", " + code : string.Empty) + ")");
        }

        private static async Task<KeyValuePair<int, byte[]>> HttpGet(string url, IDictionary<string, string> headers)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                request.Headers.TryAddWithoutValidation("User-Agent", "sunlicense-dotnet/" + SunLicenseClient.Version);
                foreach (var h in headers)
                {
                    request.Headers.TryAddWithoutValidation(h.Key, h.Value);
                }

                using (var response = await SharedHttp.SendAsync(request).ConfigureAwait(false))
                {
                    return new KeyValuePair<int, byte[]>((int)response.StatusCode, await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
                }
            }
        }

        // ---- helpers shared with the tests ----

        /// <summary>Lowercase hex SHA-256.</summary>
        public static string Digest(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return Hex(sha.ComputeHash(bytes));
            }
        }

        internal static string NormaliseDigest(string d)
        {
            var t = (d ?? string.Empty).Trim().ToLowerInvariant();
            return t.StartsWith("sha256:", StringComparison.Ordinal) ? t.Substring(7) : t;
        }

        internal static string Detail(IList<string> changed)
        {
            var b = new StringBuilder(changed.Count.ToString(CultureInfo.InvariantCulture)).Append(" changed: ");
            var shown = 0;
            foreach (var c in changed)
            {
                var next = (shown == 0 ? string.Empty : ", ") + c;
                var reserve = shown + 1 < changed.Count ? 16 : 0;
                if (b.Length + next.Length + reserve > MaxDetail)
                {
                    break;
                }

                b.Append(next);
                shown++;
            }

            if (shown < changed.Count)
            {
                b.Append(shown == 0 ? string.Empty : ", ").Append('+').Append(changed.Count - shown).Append(" more");
            }

            return b.Length > MaxDetail ? b.ToString(0, MaxDetail) : b.ToString();
        }

        /// <summary>Base64 in any flavour the server may send: url-safe or standard, with or without padding.</summary>
        internal static byte[] DecodeBase64(string s)
        {
            var t = s.Trim().Replace('-', '+').Replace('_', '/').TrimEnd('=');
            if (t.Length % 4 == 1)
            {
                throw new FormatException("not base64");
            }

            return Convert.FromBase64String(t + new string('=', (4 - t.Length % 4) % 4));
        }

        internal static string EncodeBase64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        internal static string Hex(byte[] bytes)
        {
            var b = new StringBuilder(bytes.Length * 2);
            foreach (var x in bytes)
            {
                b.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            }

            return b.ToString();
        }

        /// <summary>SHA-256 of the OS, architecture, host name and hardware addresses: what makes a copied cache file useless elsewhere.</summary>
        internal static string MachineId()
        {
            var raw = new StringBuilder();
            try
            {
                raw.Append(RuntimeInformation.OSDescription).Append('|').Append(RuntimeInformation.OSArchitecture);
            }
            catch (Exception)
            {
                raw.Append(Environment.OSVersion.Platform).Append("|?");
            }

            try
            {
                raw.Append('|').Append(Environment.MachineName);
            }
            catch (Exception)
            {
                raw.Append("|?");
            }

            try
            {
                var macs = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    {
                        continue;
                    }

                    var mac = ni.GetPhysicalAddress()?.GetAddressBytes();
                    if (mac != null && mac.Length > 0 && mac.Any(x => x != 0))
                    {
                        macs.Add(Hex(mac));
                    }
                }

                raw.Append('|').Append(string.Join(",", macs));
            }
            catch (Exception)
            {
                raw.Append("|?");
            }

            return Digest(Encoding.UTF8.GetBytes(raw.ToString()));
        }

        private static string DefaultCacheDirectory()
        {
            try
            {
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                return string.IsNullOrEmpty(home) ? null : Path.Combine(home, ".sunlicense");
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static bool ValidKey(byte[] k) => k.Length == 16 || k.Length == 24 || k.Length == 32;

        private static string Trim(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

        private static byte[] Slice(byte[] a, int offset, int count)
        {
            var r = new byte[count];
            Buffer.BlockCopy(a, offset, r, 0, count);
            return r;
        }

        // ---- the unlock cache: one file per license key, AES-GCM under a key bound to the key, the machine id and this machine ----

        private byte[] Key()
        {
            lock (_lock)
            {
                if (_unlock != null)
                {
                    return _unlock;
                }
            }

            var k = ReadCache();
            if (k != null)
            {
                lock (_lock)
                {
                    _unlock = k;
                }
            }

            return k;
        }

        internal string CacheFile()
        {
            var key = _licenseKey;
            if (_cacheDirectory == null || key == null)
            {
                return null;
            }

            var id = Digest(Encoding.UTF8.GetBytes("sunlicense-unlock-file\0" + key)).Substring(0, 16);
            return Path.Combine(_cacheDirectory, CacheFileName + id);
        }

        private byte[] CacheKey()
        {
            var binding = "sunlicense-unlock-cache\0" + _licenseKey + "\0" + (_fingerprint ?? string.Empty) + "\0" + _machine();
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(binding));
            }
        }

        private void WriteCache(byte[] key)
        {
            var file = CacheFile();
            if (file == null)
            {
                return;
            }

            try
            {
                var plain = Encoding.UTF8.GetBytes(_now().ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) + "\n" + Convert.ToBase64String(key));
                var nonce = new byte[12];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(nonce);
                }

                var sealedBytes = Gcm.Encrypt(CacheKey(), nonce, plain, new byte[0]);
                var output = new byte[nonce.Length + sealedBytes.Length];
                Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
                Buffer.BlockCopy(sealedBytes, 0, output, nonce.Length, sealedBytes.Length);
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                var tmp = file + ".tmp";
                File.WriteAllText(tmp, CachePrefix + EncodeBase64Url(output));
                if (File.Exists(file))
                {
                    File.Delete(file);
                }

                File.Move(tmp, file);
            }
            catch (Exception)
            {
                // memory only
            }
        }

        private byte[] ReadCache()
        {
            var file = CacheFile();
            if (file == null || !File.Exists(file))
            {
                return null;
            }

            try
            {
                var text = File.ReadAllText(file).Trim();
                if (!text.StartsWith(CachePrefix, StringComparison.Ordinal))
                {
                    return null;
                }

                var raw = DecodeBase64(text.Substring(CachePrefix.Length));
                var plainBytes = Gcm.Decrypt(CacheKey(), Slice(raw, 0, 12), Slice(raw, 12, raw.Length - 12), new byte[0]);
                if (plainBytes == null)
                {
                    return null; // another machine, another license key, or a damaged file
                }

                var plain = Encoding.UTF8.GetString(plainBytes);
                var nl = plain.IndexOf('\n');
                var saved = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(plain.Substring(0, nl), CultureInfo.InvariantCulture));
                var now = _now();
                if (saved > now + Skew || now >= saved + CacheTtl)
                {
                    return null; // older than 7 days, or the clock was turned back
                }

                var k = Convert.FromBase64String(plain.Substring(nl + 1));
                return ValidKey(k) ? k : null;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    /// <summary>Settings for <see cref="SunLicenseProtection"/>; only <see cref="LicenseKey"/> is needed for unlock, <see cref="ProductCode"/> too for protected files.</summary>
    public sealed class SunLicenseProtectionOptions
    {
        /// <summary>Default https://api.sunlicense.com.</summary>
        public string BaseUrl { get; set; }

        /// <summary>Your API key (protected files).</summary>
        public string ApiKey { get; set; }

        /// <summary>The license key this install checks with.</summary>
        public string LicenseKey { get; set; }

        /// <summary>The machine id it checks with.</summary>
        public string Fingerprint { get; set; }

        /// <summary>The product's code in SunLicense (protected files).</summary>
        public string ProductCode { get; set; }

        /// <summary>Product name for the notice.</summary>
        public string Product { get; set; }

        /// <summary>Owner (seller) name for the notice.</summary>
        public string Owner { get; set; }

        /// <summary>The terms link the notice ends with.</summary>
        public string Terms { get; set; }

        /// <summary>Where the unlock cache is kept (the product's data folder). Default <c>~/.sunlicense</c>.</summary>
        public string CacheDirectory { get; set; }

        /// <summary>True: keep the unlock in memory only (no 7-day cache on disk).</summary>
        public bool MemoryOnly { get; set; }

        internal Func<DateTimeOffset> Now { get; set; }

        internal Func<string> Machine { get; set; }

        internal Func<string, IDictionary<string, string>, Task<KeyValuePair<int, byte[]>>> Get { get; set; }

        internal SunLicenseProtectionOptions Copy() => (SunLicenseProtectionOptions)MemberwiseClone();
    }

    /// <summary>No unlock: the license wasn't confirmed valid (online or cached), or the data was sealed for another product.</summary>
    public sealed class SunLicenseLockedException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public SunLicenseLockedException(string message)
            : base(message)
        {
        }
    }

    /// <summary>A protected file SunLicense refused (license not valid, file missing, plan without protected files).</summary>
    public sealed class SunLicenseRefusedException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public SunLicenseRefusedException(int status, string message)
            : base(message)
        {
            Status = status;
        }

        /// <summary>The HTTP status: 401/403 refused, 404 no such file, 402 plan without protected files.</summary>
        public int Status { get; }
    }

    /// <summary>AES-GCM on the platform's AES block cipher (netstandard2.0 has no AesGcm; Mono, Unity and CitizenFX neither).</summary>
    internal static class Gcm
    {
        /// <summary>Ciphertext followed by the 16-byte tag.</summary>
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plain, byte[] aad)
        {
            using (var aes = Block(key))
            {
                var j0 = J0(aes, nonce);
                var ct = Ctr(aes, j0, plain);
                var tag = Tag(aes, j0, aad, ct);
                var output = new byte[ct.Length + 16];
                Buffer.BlockCopy(ct, 0, output, 0, ct.Length);
                Buffer.BlockCopy(tag, 0, output, ct.Length, 16);
                return output;
            }
        }

        /// <summary>The plaintext, or null when the tag doesn't match (wrong key or changed data).</summary>
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag, byte[] aad)
        {
            if ((key.Length != 16 && key.Length != 24 && key.Length != 32) || ciphertextAndTag.Length < 16)
            {
                return null;
            }

            using (var aes = Block(key))
            {
                var ct = new byte[ciphertextAndTag.Length - 16];
                Buffer.BlockCopy(ciphertextAndTag, 0, ct, 0, ct.Length);
                var j0 = J0(aes, nonce);
                var expected = Tag(aes, j0, aad, ct);
                var diff = 0;
                for (var i = 0; i < 16; i++)
                {
                    diff |= expected[i] ^ ciphertextAndTag[ct.Length + i];
                }

                return diff == 0 ? Ctr(aes, j0, ct) : null;
            }
        }

        private static ICryptoTransform Block(byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                return aes.CreateEncryptor();
            }
        }

        private static byte[] Encrypt(ICryptoTransform aes, byte[] block)
        {
            var output = new byte[16];
            aes.TransformBlock(block, 0, 16, output, 0);
            return output;
        }

        private static byte[] J0(ICryptoTransform aes, byte[] nonce)
        {
            if (nonce.Length == 12)
            {
                var j = new byte[16];
                Buffer.BlockCopy(nonce, 0, j, 0, 12);
                j[15] = 1;
                return j;
            }

            return GHash(Encrypt(aes, new byte[16]), new byte[0], nonce);
        }

        private static byte[] Ctr(ICryptoTransform aes, byte[] j0, byte[] input)
        {
            var output = new byte[input.Length];
            var counter = (byte[])j0.Clone();
            for (var i = 0; i < input.Length; i += 16)
            {
                for (var k = 15; k >= 12; k--)
                {
                    if (++counter[k] != 0)
                    {
                        break;
                    }
                }

                var ks = Encrypt(aes, counter);
                for (var k = 0; k < 16 && i + k < input.Length; k++)
                {
                    output[i + k] = (byte)(input[i + k] ^ ks[k]);
                }
            }

            return output;
        }

        private static byte[] Tag(ICryptoTransform aes, byte[] j0, byte[] aad, byte[] ct)
        {
            var s = GHash(Encrypt(aes, new byte[16]), aad, ct);
            var mask = Encrypt(aes, j0);
            for (var i = 0; i < 16; i++)
            {
                s[i] ^= mask[i];
            }

            return s;
        }

        private static byte[] GHash(byte[] h, byte[] aad, byte[] ct)
        {
            ulong hh = BigEndian(h, 0), hl = BigEndian(h, 8);
            ulong yh = 0, yl = 0;

            void Absorb(byte[] data)
            {
                for (var i = 0; i < data.Length; i += 16)
                {
                    var block = new byte[16];
                    Buffer.BlockCopy(data, i, block, 0, Math.Min(16, data.Length - i));
                    yh ^= BigEndian(block, 0);
                    yl ^= BigEndian(block, 8);
                    Mul(ref yh, ref yl, hh, hl);
                }
            }

            Absorb(aad);
            Absorb(ct);
            yh ^= (ulong)aad.Length * 8;
            yl ^= (ulong)ct.Length * 8;
            Mul(ref yh, ref yl, hh, hl);
            var output = new byte[16];
            for (var i = 0; i < 8; i++)
            {
                output[i] = (byte)(yh >> (56 - 8 * i));
                output[8 + i] = (byte)(yl >> (56 - 8 * i));
            }

            return output;
        }

        private static void Mul(ref ulong xh, ref ulong xl, ulong hh, ulong hl)
        {
            ulong zh = 0, zl = 0, vh = hh, vl = hl;
            for (var i = 0; i < 128; i++)
            {
                var bit = i < 64 ? (xh >> (63 - i)) & 1 : (xl >> (127 - i)) & 1;
                if (bit == 1)
                {
                    zh ^= vh;
                    zl ^= vl;
                }

                var lsb = vl & 1;
                vl = (vl >> 1) | (vh << 63);
                vh >>= 1;
                if (lsb == 1)
                {
                    vh ^= 0xE100000000000000UL;
                }
            }

            xh = zh;
            xl = zl;
        }

        private static ulong BigEndian(byte[] b, int offset)
        {
            ulong v = 0;
            for (var i = 0; i < 8; i++)
            {
                v = (v << 8) | b[offset + i];
            }

            return v;
        }
    }

    /// <summary>A small JSON reader: objects → IDictionary, arrays → IList, numbers → double, strings, booleans, null.</summary>
    internal sealed class MiniJson
    {
        private readonly string _s;
        private int _i;

        private MiniJson(string s) => _s = s;

        /// <summary>The parsed value, or null when the text isn't JSON.</summary>
        public static object TryParse(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                return null;
            }

            try
            {
                var p = new MiniJson(s);
                var v = p.Value();
                p.Ws();
                return p._i == s.Length ? v : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private void Ws()
        {
            while (_i < _s.Length && char.IsWhiteSpace(_s[_i]))
            {
                _i++;
            }
        }

        private object Value()
        {
            Ws();
            var c = _s[_i];
            if (c == '{')
            {
                _i++;
                var m = new Dictionary<string, object>(StringComparer.Ordinal);
                Ws();
                if (_s[_i] == '}')
                {
                    _i++;
                    return m;
                }

                while (true)
                {
                    Ws();
                    var k = Str();
                    Ws();
                    Expect(':');
                    m[k] = Value();
                    Ws();
                    if (_s[_i] == '}')
                    {
                        _i++;
                        return m;
                    }

                    Expect(',');
                }
            }

            if (c == '[')
            {
                _i++;
                var l = new List<object>();
                Ws();
                if (_s[_i] == ']')
                {
                    _i++;
                    return l;
                }

                while (true)
                {
                    l.Add(Value());
                    Ws();
                    if (_s[_i] == ']')
                    {
                        _i++;
                        return l;
                    }

                    Expect(',');
                }
            }

            if (c == '"')
            {
                return Str();
            }

            if (Word("true"))
            {
                return true;
            }

            if (Word("false"))
            {
                return false;
            }

            if (Word("null"))
            {
                return null;
            }

            var start = _i;
            while (_i < _s.Length && "+-0123456789.eE".IndexOf(_s[_i]) >= 0)
            {
                _i++;
            }

            return double.Parse(_s.Substring(start, _i - start), NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        private bool Word(string w)
        {
            if (string.CompareOrdinal(_s, _i, w, 0, w.Length) != 0)
            {
                return false;
            }

            _i += w.Length;
            return true;
        }

        private void Expect(char c)
        {
            if (_s[_i] != c)
            {
                throw new FormatException("expected " + c);
            }

            _i++;
        }

        private string Str()
        {
            Expect('"');
            var b = new StringBuilder();
            while (true)
            {
                var c = _s[_i++];
                if (c == '"')
                {
                    return b.ToString();
                }

                if (c != '\\')
                {
                    b.Append(c);
                    continue;
                }

                var e = _s[_i++];
                switch (e)
                {
                    case 'b': b.Append('\b'); break;
                    case 'f': b.Append('\f'); break;
                    case 'n': b.Append('\n'); break;
                    case 'r': b.Append('\r'); break;
                    case 't': b.Append('\t'); break;
                    case 'u':
                        b.Append((char)int.Parse(_s.Substring(_i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        _i += 4;
                        break;
                    default: b.Append(e); break;
                }
            }
        }
    }
}
