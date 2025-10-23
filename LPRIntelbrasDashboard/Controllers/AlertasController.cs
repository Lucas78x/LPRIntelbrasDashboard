using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

public class AlertasController : Controller
{
    private readonly IHubContext<LPRHub> _hubContext;
    private readonly ILogger<AlertasController> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _apiBaseUrl;

    public AlertasController(
        IHubContext<LPRHub> hubContext,
        ILogger<AlertasController> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _hubContext = hubContext;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _apiBaseUrl = configuration["ApiBaseUrl"] ?? "http://45.187.55.245:7195/api/v1/alerta";
    }

    /// <summary>
    /// Exibe a página de gerenciamento de alertas.
    /// </summary>
    public async Task<IActionResult> Alertas()
    {
        if (!ValidateToken())
        {
            _logger.LogWarning("Sessão inválida ou token expirado. Redirecionando para login.");
            ClearSession();
            return RedirectToAction("Login", "Account");
        }

        try
        {
            var alertas = await ObterAlertasDoUsuario();
            return View(alertas);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar página de alertas.");

            var errorModel = new ErrorViewModel
            {
                RequestId = HttpContext.TraceIdentifier,
                Message = ex.Message,
                StackTrace = ex.StackTrace
            };

            return View("Error", errorModel);
        }

    }

    /// <summary>
    /// Busca alertas do usuário autenticado na API.
    /// </summary>
    private async Task<List<Alerta>> ObterAlertasDoUsuario()
    {
        var handler = new HttpClientHandler()
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        var client = new HttpClient(handler);

        var token = HttpContext.Session.GetString("Token");

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync($"{_apiBaseUrl}/listar");
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var alertas = JsonSerializer.Deserialize<List<Alerta>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        return alertas ?? new List<Alerta>();
    }

    /// <summary>
    /// Valida o token JWT armazenado na sessão.
    /// </summary>
    private bool ValidateToken()
    {
        var token = HttpContext.Session.GetString("Token");
        if (string.IsNullOrWhiteSpace(token))
            return false;

        try
        {
            var handler = new JwtSecurityTokenHandler();
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
    /// Remove dados da sessão (logout seguro).
    /// </summary>
    private void ClearSession()
    {
        HttpContext.Session.Remove("Token");
        HttpContext.Session.Remove("User");
        _logger.LogInformation("Sessão limpa com sucesso.");
    }
}
