using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace LPRIntelbrasDashboard.Services
{
  
    public interface ILPRService
    {
        Task<bool> ExportDataFromDevice(string ipAddress);
    }

    public class LPRService : ILPRService
    {
        private readonly HttpClient _httpClient;
        private readonly ICSVService _csvService;
        private int _ncCount = 1;

        public LPRService(ICSVService csvService)
        {
            _httpClient = new HttpClient();
            _csvService = csvService;
        }

        public async Task<bool> ExportDataFromDevice(string ipAddress)
        {
            try
            {
                string filename = $"Veic_Flux_{DateTime.UtcNow:dd_MM_yyyy_HH_mm_ss}";
                long unixStartTime = new DateTimeOffset(DateTime.UtcNow.AddDays(-2)).ToUnixTimeSeconds();
                long unixEndTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string password = "152535ff", username = "admin";

                string[] urls = {
                $"http://{ipAddress}/cgi-bin/recordUpdater.cgi?action=exportAsyncFileByConditon&name=TrafficSnapEventInfo&filename={filename}&format=CSV&code=utf-8&condition.startTime={unixStartTime}&condition.endTime={unixEndTime}",
                $"http://{ipAddress}/cgi-bin/recordUpdater.cgi?action=getFileExportState&name=TrafficSnapEventInfo",
                $"http://{ipAddress}/cgi-bin/trafficRecord.cgi?action=downloadFile&Type=TrafficSnapEventInfo&filename={filename}"
            };

                // 1. Autenticar
                string authHeader = await AuthenticateAsync(urls[0], username, password);
                if (authHeader == null) return false;

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", authHeader);

                // 2. Iniciar exportação
                var exportResponse = await _httpClient.GetAsync(urls[0]);
                if (!exportResponse.IsSuccessStatusCode) return false;

                // 3. Verificar estado da exportação
                int state;
                do
                {
                    await Task.Delay(2000);
                    authHeader = await AuthenticateAsync(urls[1], username, password);
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", authHeader);

                    var stateResponse = await _httpClient.GetAsync(urls[1]);
                    if (!stateResponse.IsSuccessStatusCode) return false;

                    var stateContent = await stateResponse.Content.ReadAsStringAsync();
                    if (!int.TryParse(stateContent.Split('=')[1], out state)) return false;

                } while (state == 2);

                if (state != 0) return false;

                // 4. Baixar arquivo
                authHeader = await AuthenticateAsync(urls[2], username, password);
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", authHeader);

                var downloadResponse = await _httpClient.GetAsync(urls[2]);
                if (!downloadResponse.IsSuccessStatusCode) return false;

                var fileData = await downloadResponse.Content.ReadAsByteArrayAsync();

                string folder = GetFolderName(ipAddress);
                string directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "Data", folder);
                string filepath = Path.Combine(directoryPath, $"{filename}.csv");

                // Cria o diretório se não existir
                Directory.CreateDirectory(directoryPath);

                // Grava o arquivo
                await File.WriteAllBytesAsync(filepath, fileData);

                // Processar CSV
                await _csvService.ProcessCSV(filepath, ipAddress);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<string> AuthenticateAsync(string url, string username, string password)
        {
            var authResponse = await _httpClient.GetAsync(url);

            if (authResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                var digestParams = ParseDigestHeader(authResponse.Headers.WwwAuthenticate.ToString());
                string nonce = digestParams["nonce"];
                string realm = digestParams["realm"];
                string qop = digestParams["qop"];
                string opaque = digestParams["opaque"];

                string nc = (_ncCount++).ToString("X8");
                string cnonce = GenerateCNonce();

                string responseHash = CalculateDigestResponse(username, password, realm, nonce, nc, cnonce, qop, "GET", url);

                return $"username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", nc={nc}, cnonce=\"{cnonce}\", qop={qop}, uri=\"{url}\", response=\"{responseHash}\", opaque=\"{opaque}\"";
            }
            return null;
        }

        private string GetFolderName(string ipAddress)
        {
            return ipAddress switch
            {
                "192.168.9.100" => "ASCON",
                "192.168.9.101" => "Genipapu",
                "192.168.13.103" => "CondSol",
                _ => "Other"
            };
        }

        private Dictionary<string, string> ParseDigestHeader(string authHeader)
        {
            var parameters = new Dictionary<string, string>();
            var regex = new Regex(@"(\w+)=(""([^""]*)""|([^,""]+))");
            var matches = regex.Matches(authHeader);

            foreach (Match match in matches)
            {
                string key = match.Groups[1].Value;
                string value = match.Groups[3].Success ? match.Groups[3].Value : match.Groups[4].Value;
                parameters[key] = value;
            }

            return parameters;
        }

        private string GenerateCNonce() => Guid.NewGuid().ToString("N");

        private string CalculateDigestResponse(string username, string password, string realm, string nonce, string nc, string cnonce, string qop, string method, string uri)
        {
            var ha1 = CalculateMD5($"{username}:{realm}:{password}");
            var ha2 = CalculateMD5($"{method}:{uri}");
            return CalculateMD5($"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}");
        }

        private string CalculateMD5(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
