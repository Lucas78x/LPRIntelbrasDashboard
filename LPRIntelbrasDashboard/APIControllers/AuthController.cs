using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using LPRIntelbrasDashboard.Jwt;
using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;

[ApiController]
[Route("api/v1/[controller]")]
[EnableRateLimiting("fixed")]
public class AuthController : ControllerBase
{
    private readonly UserManager<UsuarioDTO> _userManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;
    private readonly JwtSettings _jwtSettings;

    public AuthController(
        UserManager<UsuarioDTO> userManager,
        IConfiguration configuration,
        ILogger<AuthController> logger,
        IOptions<JwtSettings> jwtSettings)
    {
        _userManager = userManager;
        _configuration = configuration;
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
    }

    /// <summary>
    /// Efetua login e retorna tokens de acesso
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LPRIntelbrasDashboard.Models.LoginRequest request)
    {
        try
        {
            // Validação do modelo
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userCreate = new UsuarioDTO { Nome = "Flavio",UserName = "Flavio", Email = request.Email };
            var result = await _userManager.CreateAsync(userCreate, request.Password);
            // Busca o usuário pelo email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning($"Tentativa de login com email não cadastrado: {request.Email}");
                return Unauthorized("Credenciais inválidas");
            }

            // Verifica a senha
            if (!await _userManager.CheckPasswordAsync(user, request.Password))
            {
                _logger.LogWarning($"Tentativa de login com senha incorreta para o usuário: {user.Id}");
                return Unauthorized("Credenciais inválidas");
            }

            // Gera o token JWT
            var token = await GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            // Armazena o refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);
            await _userManager.UpdateAsync(user);

            _logger.LogInformation($"Login bem-sucedido para o usuário: {user.Id}");

            return Ok(new AuthResponse
            {
                Token = token,
                RefreshToken = refreshToken,
                ExpiresIn = _jwtSettings.TokenExpiryInMinutes * 60
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro durante o processo de login");
            return StatusCode(500, "Erro interno no servidor");
        }
    }

    /// <summary>
    /// Renova o token de acesso usando o refresh token
    /// </summary>
    [HttpPost("refresh-token")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var principal = GetPrincipalFromExpiredToken(request.Token);
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || user.RefreshToken != request.RefreshToken ||
                user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Unauthorized("Token de atualização inválido");
            }

            var newToken = await GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponse
            {
                Token = newToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = _jwtSettings.TokenExpiryInMinutes * 60
            });
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Token JWT inválido");
            return Unauthorized("Token inválido");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao renovar token");
            return StatusCode(500, "Erro interno no servidor");
        }
    }

    /// <summary>
    /// Revoga o refresh token do usuário
    /// </summary>
    [HttpPost("revoke-token")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeToken()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId);

        user.RefreshToken = null;
        await _userManager.UpdateAsync(user);

        return NoContent();
    }

    private async Task<string> GenerateJwtToken(UsuarioDTO user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, user.Nome)
        };

        // Adiciona roles do usuário
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryInMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Token inválido");

        return principal;
    }
}