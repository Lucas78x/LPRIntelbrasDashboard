using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using CsvHelper;
using System.Globalization;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using LPRIntelbrasDashboard.Models;
using Microsoft.Extensions.Logging;

namespace LPRIntelbrasDashboard.Controllers
{
    public class DashboardController : Controller
    {
        private readonly IHubContext<LPRHub> _hubContext;
        private readonly ILogger<DashboardController> _logger;
        private readonly string _dataFile;

        public DashboardController(IHubContext<LPRHub> hubContext, ILogger<DashboardController> logger)
        {
            _hubContext = hubContext;
            _logger = logger;
            _dataFile = Path.Combine(Directory.GetCurrentDirectory(), "Data", "MergedData.csv");
        }

        /// <summary>
        /// Exibe o painel principal com filtros aplicáveis.
        /// </summary>
        public IActionResult Dashboard(string filtroPlaca = "", string regiao = "", string data = "")
        {
            if (!ValidateToken())
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

        /// <summary>
        /// Valida o token JWT armazenado na sessão.
        /// </summary>
        private bool ValidateToken()
        {
            var token = HttpContext.Session.GetString("Token");
            if (string.IsNullOrWhiteSpace(token))
                return false;

            var handler = new JwtSecurityTokenHandler();

            try
            {
                var jwtToken = handler.ReadJwtToken(token);
                return jwtToken.ValidTo > DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao validar token JWT.");
                return false;
            }
        }

        /// <summary>
        /// Constrói o modelo de visualização do Dashboard aplicando filtros.
        /// </summary>
        private static DashboardViewModel BuildDashboardViewModel(string filtroPlaca, string regiao, string data, List<RegistroCSV> registros)
        {
            IEnumerable<RegistroCSV> query = registros;

            if (!string.IsNullOrEmpty(filtroPlaca))
                query = query.Where(r => r.NPlaca.Contains(filtroPlaca, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(regiao) && !regiao.Equals("Todos", StringComparison.OrdinalIgnoreCase))
                query = query.Where(r => r.Região.Equals(regiao, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(data))
                query = query.Where(r => r.DataHora.StartsWith(data));

            // Garante ordenação e filtragem apenas de datas válidas
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

        /// <summary>
        /// Carrega os registros do CSV de forma segura e robusta.
        /// </summary>
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

        /// <summary>
        /// Remove os dados da sessão de forma segura.
        /// </summary>
        private void ClearSession()
        {
            HttpContext.Session.Remove("Token");
            HttpContext.Session.Remove("User");
            _logger.LogInformation("Sessão limpa com sucesso.");
        }
    }
}
