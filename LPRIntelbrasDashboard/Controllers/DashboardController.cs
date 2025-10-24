using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using CsvHelper;
using System.Globalization;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using LPRIntelbrasDashboard.Models;
using Microsoft.Extensions.Logging;

namespace LPRIntelbrasDashboard.Controllers
{
    public class DashboardController : Controller
    {
        private readonly IHubContext<LPRHub> _hubContext;
        private readonly ILogger<DashboardController> _logger;
        private readonly string _dataFile;
        private const string ApiBaseUrl = "https://45.187.55.245:7195/api/v1/auth";

        public DashboardController(IHubContext<LPRHub> hubContext, ILogger<DashboardController> logger)
        {
            _hubContext = hubContext;
            _logger = logger;
            _dataFile = Path.Combine(Directory.GetCurrentDirectory(), "Data", "MergedData.csv");
        }

        /// <summary>
        /// Exibe o painel principal com filtros aplicáveis.
        /// </summary>
        public async Task<IActionResult> Dashboard(string filtroPlaca = "", string regiao = "", string data = "")
        {
            if (!await EnsureValidSessionTokenAsync())
            {
                _logger.LogWarning("Sessão inválida ou token expirado. Redirecionando para login.");
                ClearSession();
                return RedirectToAction("Login", "Account");
            }

            try
            {
                var registros = LoadRegistrosFromCsv();
                var model = BuildDashboardViewModel(filtroPlaca, regiao, data, registros);

                _logger.LogInformation("Total de registros carregados: {count}", model.TotalPlacas);
                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao carregar registros ou montar o dashboard.");
                return View("Error", ex);
            }
        }

        private async Task<bool> EnsureValidSessionTokenAsync()
        {
            var token = HttpContext.Session.GetString("Token");
            var refreshToken = HttpContext.Session.GetString("RefreshToken");
            var expireStr = HttpContext.Session.GetString("TokenExpireUtc");

            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(refreshToken))
                return false;

            if (!DateTime.TryParse(expireStr, out var expireUtc))
            {
                _logger.LogWarning("Data de expiração do token inválida na sessão.");
                return false;
            }

            // Se ainda está válido, retorna true
            if (expireUtc > DateTime.UtcNow.AddSeconds(30))
                return true;

            // Caso contrário, tenta renovar o token
            _logger.LogInformation("Token expirado, tentando renovação automática...");

            try
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };

                using var client = new HttpClient(handler);
                var refreshPayload = new
                {
                    Token = token,
                    RefreshToken = refreshToken
                };

                var content = new StringContent(JsonSerializer.Serialize(refreshPayload), Encoding.UTF8, "application/json");
                var response = await client.PostAsync($"{ApiBaseUrl}/refresh-token", content);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Falha ao renovar token. Código: {code}", response.StatusCode);
                    return false;
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<AuthResponse>(jsonResponse,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (tokenResponse is null)
                {
                    _logger.LogWarning("Falha ao desserializar resposta do refresh token.");
                    return false;
                }

                SaveSession(tokenResponse);
                _logger.LogInformation("Token renovado com sucesso para {user}", tokenResponse.UserEmail);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao tentar renovar token automaticamente.");
                return false;
            }
        }

        private void SaveSession(AuthResponse auth)
        {
            HttpContext.Session.SetString("Token", auth.Token);
            HttpContext.Session.SetString("RefreshToken", auth.RefreshToken);
            HttpContext.Session.SetString("User", auth.UserEmail ?? "");
            HttpContext.Session.SetString("TokenExpireUtc", auth.ExpirationUtc.ToString("o"));
        }

        private void ClearSession()
        {
            HttpContext.Session.Remove("Token");
            HttpContext.Session.Remove("RefreshToken");
            HttpContext.Session.Remove("User");
            HttpContext.Session.Remove("TokenExpireUtc");
            _logger.LogInformation("Sessão limpa com sucesso.");
        }

        private static DashboardViewModel BuildDashboardViewModel(string filtroPlaca, string regiao, string data, List<RegistroCSV> registros)
        {
            IEnumerable<RegistroCSV> query = registros;

            if (!string.IsNullOrEmpty(filtroPlaca))
                query = query.Where(r => r.NPlaca.Contains(filtroPlaca, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(regiao) && !regiao.Equals("Todos", StringComparison.OrdinalIgnoreCase))
                query = query.Where(r => r.Região.Equals(regiao, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(data))
                query = query.Where(r => r.DataHora.StartsWith(data));

            var registrosFiltrados = query
                .Where(r => DateTime.TryParse(r.DataHora, out _))
                .OrderByDescending(r => DateTime.Parse(r.DataHora))
                .ToList();

            return new DashboardViewModel
            {
                Registros = registrosFiltrados,
                FiltroPlaca = filtroPlaca,
                Regiao = regiao,
                Data = data
            };
        }

        private List<RegistroCSV> LoadRegistrosFromCsv()
        {
            var registros = new List<RegistroCSV>();

            if (!System.IO.File.Exists(_dataFile))
            {
                _logger.LogWarning("Arquivo CSV não encontrado em {path}.", _dataFile);
                return registros;
            }

            try
            {
                using var reader = new StreamReader(_dataFile, new UTF8Encoding(true));
                using var csv = new CsvReader(reader, CultureInfo.InvariantCulture);

                registros = csv.GetRecords<RegistroCSV>()
                    .Where(r => !string.IsNullOrWhiteSpace(r.NPlaca))
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao ler o arquivo CSV.");
                throw;
            }

            return registros;
        }
    }
}
