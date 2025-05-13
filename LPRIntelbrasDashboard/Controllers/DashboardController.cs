using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using CsvHelper;
using System.Globalization;
using System.Text;
using LPRIntelbrasDashboard.Models;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace LPRIntelbrasDashboard.Controllers
{
    public class DashboardController : Controller
    {
        private readonly IHubContext<LPRHub> _hubContext;
        private readonly string _dataFile = Path.Combine(Directory.GetCurrentDirectory(), "Data", "MergedData.csv");

        public DashboardController(IHubContext<LPRHub> hubContext)
        {
            _hubContext = hubContext;
        }

        public IActionResult Dashboard(string filtroPlaca = "", string regiao = "", string data = "")
        {
            if (!ValidateToken())
            {
                RemoveSession();
                return RedirectToAction("Login", "Account");
            }

            List<RegistroCSV> registros = RegistrosByCSV();

            DashboardViewModel model = CreateDashboardModel(filtroPlaca, regiao, data, ref registros);

            return View(model);
        }


        private bool ValidateToken()
        {
            var token = HttpContext.Session.GetString("Token");

            if (string.IsNullOrEmpty(token))
                return false;

            var handler = new JwtSecurityTokenHandler();

            try
            {
                var jwtToken = handler.ReadJwtToken(token);
                var expiration = jwtToken.ValidTo;
                if (expiration < DateTime.UtcNow)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static DashboardViewModel CreateDashboardModel(string filtroPlaca, string regiao, string data, ref List<RegistroCSV> registros)
        {
            if (!string.IsNullOrEmpty(filtroPlaca))
                registros = registros.Where(r => r.NPlaca.Contains(filtroPlaca, StringComparison.OrdinalIgnoreCase)).ToList();

            if (!string.IsNullOrEmpty(regiao) && regiao != "Todos")
                registros = registros.Where(r => r.Região == regiao).ToList();

            if (!string.IsNullOrEmpty(data))
                registros = registros.Where(r => r.DataHora.StartsWith(data)).ToList();

            registros = registros
           .Where(r => DateTime.TryParse(r.DataHora, out _))
           .OrderByDescending(r => DateTime.Parse(r.DataHora))
           .ToList();

            foreach(var registro in registros)
            {
                Console.WriteLine($"DataHora: {registro.DataHora}");
            }

            var model = new DashboardViewModel
            {
                Registros = registros,
                FiltroPlaca = filtroPlaca,
                Regiao = regiao,
                Data = data
            };
            return model;
        }

        private List<RegistroCSV> RegistrosByCSV()
        {
            var registros = new List<RegistroCSV>();
            if (System.IO.File.Exists(_dataFile))
            {
                using var reader = new StreamReader(_dataFile, new UTF8Encoding(true));
                using var csv = new CsvReader(reader, CultureInfo.InvariantCulture);
                registros = csv.GetRecords<RegistroCSV>()
                    .Where(r => !string.IsNullOrWhiteSpace(r.NPlaca))
                    .ToList();
            }

            return registros;
        }
        private void RemoveSession()
        {
            HttpContext.Session.Remove("Token");
            HttpContext.Session.Remove("User");
        }

    }
}
