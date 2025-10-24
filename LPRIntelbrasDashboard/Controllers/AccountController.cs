using LPRIntelbrasDashboard.Models;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Json;

public class AccountController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;
    private const string ApiBaseUrl = "https://45.187.55.245:7195/api/v1/auth";

    public AccountController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet]
    public async Task<IActionResult> Login()
    {
        // se já tem sessão válida -> manda direto pro dashboard
        if (await HasValidOrRefreshedTokenAsync())
            return RedirectToAction("Dashboard", "Dashboard");

        // senão mostra tela de login
        ClearSession();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ValidateLogin([FromForm] LoginRequest login)
    {
        if (!ModelState.IsValid)
        {
            ViewBag.ErrorMessage = "Usuário ou senha inválidos.";
            return View("Login");
        }

        // cria client que ignora SSL (p/ ambiente interno/self-signed)
        var client = CreateUnsafeClient();

        var content = new StringContent(JsonSerializer.Serialize(login), Encoding.UTF8, "application/json");
        var response = await client.PostAsync($"{ApiBaseUrl}/login", content);

        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                ViewBag.ErrorMessage = "Email ou senha inválidos.";
            else
                ViewBag.ErrorMessage = $"Não foi possível fazer login. Erro {response.StatusCode}";

            return View("Login");
        }

        // login ok
        var jsonResponse = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<AuthResponse>(jsonResponse,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        SaveSession(tokenResponse);

        return RedirectToAction("Dashboard", "Dashboard");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await RevokeTokenAsync();
        ClearSession();
        return RedirectToAction("Login", "Account");
    }

    private HttpClient CreateUnsafeClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        return new HttpClient(handler);
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
    }

    private async Task<bool> HasValidOrRefreshedTokenAsync()
    {
        var token = HttpContext.Session.GetString("Token");
        var refreshToken = HttpContext.Session.GetString("RefreshToken");
        var expiresStr = HttpContext.Session.GetString("TokenExpireUtc");

        if (string.IsNullOrWhiteSpace(token) ||
            string.IsNullOrWhiteSpace(refreshToken) ||
            string.IsNullOrWhiteSpace(expiresStr))
            return false;

        if (!DateTime.TryParse(expiresStr, out var expireUtc))
            return false;

        if (expireUtc > DateTime.UtcNow.AddSeconds(30))
            return true;

        var client = CreateUnsafeClient();
        var refreshPayload = new RefreshTokenRequest
        {
            Token = token,
            RefreshToken = refreshToken
        };

        var content = new StringContent(JsonSerializer.Serialize(refreshPayload), Encoding.UTF8, "application/json");
        var response = await client.PostAsync($"{ApiBaseUrl}/refresh-token", content);

        if (!response.IsSuccessStatusCode)
        {
            return false;
        }

        var jsonResponse = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<AuthResponse>(jsonResponse,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        SaveSession(tokenResponse);
        return true;
    }

    private async Task RevokeTokenAsync()
    {
        var token = HttpContext.Session.GetString("Token");
        if (string.IsNullOrWhiteSpace(token))
            return;

        var client = CreateUnsafeClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        try
        {
            await client.PostAsync($"{ApiBaseUrl}/revoke-token", null);
        }
        catch
        {

        }
    }
}
