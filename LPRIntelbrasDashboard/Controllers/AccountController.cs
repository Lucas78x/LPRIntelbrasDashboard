using CsvHelper;
using LPRIntelbrasDashboard.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class AccountController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;

    public AccountController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet]
    public async Task<IActionResult> Login()
    {
        var token = HttpContext.Session.GetString("Token");
        if (token != null && !ValidateToken())
        {
            RemoveSession();
            return RedirectToAction("Dashboard", "Dashboard");
        }
        return View();
    }

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
            return false;
        }
    }

    private void ClearSession()
    {
        HttpContext.Session.Remove("Token");
        HttpContext.Session.Remove("User");
    }

    [HttpPost]
    public async Task<IActionResult> ValidateLogin([FromForm] LoginRequest login)
    {
        if (ModelState.IsValid)
        {
            var handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            var client = new HttpClient(handler);

            var content = new StringContent(JsonSerializer.Serialize(login), Encoding.UTF8, "application/json");
            var response = await client.PostAsync("https://45.187.55.245:7195/api/v1/auth/login", content);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<AuthResponse>(jsonResponse, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                HttpContext.Session.SetString("Token", tokenResponse.Token);
                HttpContext.Session.SetString("RefreshToken", tokenResponse.RefreshToken);
                HttpContext.Session.SetString("User", login.Email);

                return RedirectToAction("Dashboard", "Dashboard");
            }
            else
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    ViewBag.ErrorMessage = "Email ou senha invalidos.";
                }
                else
                {
                    ViewBag.ErrorMessage = $"Nao foi possivel fazer login, erro {response.StatusCode}";
                }
            }
        }

        ViewBag.ErrorMessage = "Usuário ou senha inválidos!";
        return View("Login");
    }
    public async Task<IActionResult> Logout()
    {
        await RevokeToken();
        RemoveSession();
        return RedirectToAction("Login", "Account");
    }

    private void RemoveSession()
    {
        HttpContext.Session.Remove("Token");
        HttpContext.Session.Remove("User");
    }

    private async Task RevokeToken()
    {
        var token = HttpContext.Session.GetString("Token");
        if (!string.IsNullOrEmpty(token))
        {
            var handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            var client = new HttpClient(handler);
            var response = await client.PostAsync("https://45.187.55.245:7195/api/v1/auth/revoke-token", null);
        }
    }
}
