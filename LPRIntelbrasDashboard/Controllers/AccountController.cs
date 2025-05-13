using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using LPRIntelbrasDashboard.Models;
using CsvHelper;
using System.Globalization;
using System.Net;

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
        if (token != null)
        {
            return RedirectToAction("Dashboard", "Dashboard");
        }
        return View();
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
            var response = await client.PostAsync("https://172.30.2.163:7195/api/v1/auth/login", content);

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
            var response = await client.PostAsync("https://172.30.2.163:7195/api/v1/auth/revoke-token", null);
        }
    }
}
