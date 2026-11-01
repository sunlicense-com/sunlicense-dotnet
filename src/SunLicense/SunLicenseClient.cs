using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SunLicense
{
    /// <summary>
    /// Official SunLicense client for .NET.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Early release. Licence validation works against the SunLicense REST API; the wider
    /// client surface (activations, entitlements, offline verification) is in development.
    /// </para>
    /// <para>
    /// This client has no third-party dependencies, so it is safe to ship inside a FiveM
    /// resource or a desktop application without assembly conflicts.
    /// </para>
    /// <example>
    /// <code>
    /// using var client = new SunLicenseClient("https://your-instance.example.com");
    /// var result = await client.ValidateAsync("LICENCE-KEY-HERE");
    /// if (result.IsValid)
    /// {
    ///     Console.WriteLine("Licence valid");
    /// }
    /// </code>
    /// </example>
    /// </remarks>
    public sealed class SunLicenseClient : IDisposable
    {
        /// <summary>The version of this client.</summary>
        public const string Version = "0.1.0";

        private readonly string _baseUrl;
        private readonly string _token;
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;
        private bool _disposed;

        /// <summary>
        /// Creates a client for the given SunLicense instance.
        /// </summary>
        /// <param name="baseUrl">Base URL of your SunLicense instance.</param>
        /// <param name="token">API token, if your endpoint requires one.</param>
        /// <param name="timeout">Request timeout. Defaults to 10 seconds.</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="baseUrl"/> is null or empty.</exception>
        public SunLicenseClient(string baseUrl, string token = null, TimeSpan? timeout = null)
        {
            if (string.IsNullOrEmpty(baseUrl))
            {
                throw new ArgumentException("baseUrl must not be null or empty", nameof(baseUrl));
            }

            _baseUrl = baseUrl.TrimEnd('/');
            _token = token;
            _httpClient = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(10) };
            _ownsHttpClient = true;
        }

        /// <summary>
        /// Creates a client that reuses an existing <see cref="HttpClient"/>.
        /// </summary>
        /// <param name="httpClient">The client to use. It is not disposed by this instance.</param>
        /// <param name="baseUrl">Base URL of your SunLicense instance.</param>
        /// <param name="token">API token, if your endpoint requires one.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpClient"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="baseUrl"/> is null or empty.</exception>
        public SunLicenseClient(HttpClient httpClient, string baseUrl, string token = null)
        {
            if (string.IsNullOrEmpty(baseUrl))
            {
                throw new ArgumentException("baseUrl must not be null or empty", nameof(baseUrl));
            }

            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _baseUrl = baseUrl.TrimEnd('/');
            _token = token;
            _ownsHttpClient = false;
        }

        /// <summary>
        /// Validates a licence key.
        /// </summary>
        /// <param name="licenseKey">The licence key to check.</param>
        /// <param name="context">Optional extra fields, for example <c>product</c> or <c>host</c>.</param>
        /// <param name="cancellationToken">A token to cancel the request.</param>
        /// <returns>The outcome of the validation.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="licenseKey"/> is null or empty.</exception>
        /// <exception cref="SunLicenseException">Thrown when the request fails.</exception>
        public async Task<ValidationResult> ValidateAsync(
            string licenseKey,
            IDictionary<string, string> context = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(licenseKey))
            {
                throw new ArgumentException("licenseKey must not be null or empty", nameof(licenseKey));
            }

            var payload = new Dictionary<string, string> { ["license"] = licenseKey };
            if (context != null)
            {
                foreach (var pair in context)
                {
                    payload[pair.Key] = pair.Value;
                }
            }

            using (var request = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "/api/v2/license/validate"))
            {
                request.Content = new StringContent(ToJson(payload), Encoding.UTF8, "application/json");
                request.Headers.TryAddWithoutValidation("User-Agent", "sunlicense-dotnet/" + Version);

                if (!string.IsNullOrEmpty(_token))
                {
                    request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _token);
                }

                try
                {
                    using (var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false))
                    {
                        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        return new ValidationResult(response.IsSuccessStatusCode, (int)response.StatusCode, body);
                    }
                }
                catch (HttpRequestException e)
                {
                    throw new SunLicenseException("SunLicense request failed", e);
                }
                catch (TaskCanceledException e) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new SunLicenseException("SunLicense request timed out", e);
                }
            }
        }

        /// <summary>
        /// Starts built-in product analytics for a licensed product, with this client's base URL and API key:
        /// a report every 30 minutes in the background (see <see cref="SunLicenseAnalytics"/>). Never throws.
        /// </summary>
        /// <param name="licenseKey">The license key you validate.</param>
        /// <param name="fingerprint">The machine id you validate with (<c>host</c>).</param>
        /// <param name="options">Other settings (product version, switch, product analytics id…).</param>
        /// <returns>The reporter; dispose it when the product shuts down.</returns>
        public SunLicenseAnalytics Analytics(string licenseKey, string fingerprint, SunLicenseAnalyticsOptions options = null)
        {
            var o = (options ?? new SunLicenseAnalyticsOptions()).Copy();
            o.BaseUrl = o.BaseUrl ?? _baseUrl;
            o.ApiKey = o.ApiKey ?? _token;
            o.LicenseKey = licenseKey;
            o.Fingerprint = fingerprint;
            return SunLicenseAnalytics.Start(o);
        }

        /// <summary>Serialises a flat string dictionary to JSON without a JSON library.</summary>
        private static string ToJson(IDictionary<string, string> values)
        {
            var json = new StringBuilder("{");
            var first = true;

            foreach (var pair in values)
            {
                if (!first)
                {
                    json.Append(',');
                }

                first = false;
                json.Append('"').Append(Escape(pair.Key)).Append("\":\"").Append(Escape(pair.Value)).Append('"');
            }

            return json.Append('}').ToString();
        }

        private static string Escape(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            var output = new StringBuilder(value.Length);

            foreach (var c in value)
            {
                switch (c)
                {
                    case '"': output.Append("\\\""); break;
                    case '\\': output.Append("\\\\"); break;
                    case '\n': output.Append("\\n"); break;
                    case '\r': output.Append("\\r"); break;
                    case '\t': output.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            output.Append(c);
                        }

                        break;
                }
            }

            return output.ToString();
        }

        /// <summary>Releases the underlying <see cref="HttpClient"/> when this instance created it.</summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
        }
    }

    /// <summary>The outcome of a licence validation call.</summary>
    public sealed class ValidationResult
    {
        internal ValidationResult(bool isValid, int statusCode, string body)
        {
            IsValid = isValid;
            StatusCode = statusCode;
            Body = body;
        }

        /// <summary>Gets a value indicating whether the server accepted the licence.</summary>
        public bool IsValid { get; }

        /// <summary>Gets the HTTP status code of the response.</summary>
        public int StatusCode { get; }

        /// <summary>Gets the raw response body, which callers may parse as JSON if needed.</summary>
        public string Body { get; }

        /// <inheritdoc/>
        public override string ToString()
        {
            return string.Format(
                CultureInfo.InvariantCulture,
                "ValidationResult {{ IsValid = {0}, StatusCode = {1} }}",
                IsValid,
                StatusCode);
        }
    }

    /// <summary>Thrown when a SunLicense request cannot be completed.</summary>
    public sealed class SunLicenseException : Exception
    {
        /// <summary>Creates the exception.</summary>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The underlying cause.</param>
        public SunLicenseException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
