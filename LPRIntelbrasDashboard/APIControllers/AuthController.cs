using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using LPRIntelbrasDashboard.Jwt;
using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;

[ApiController]
[Route("api/v1/[controller]")]
[EnableRateLimiting("fixed")]
public class AuthController : ControllerBase
{
    private readonly UserManager<UsuarioDTO> _userManager;
    private readonly ILogger<AuthController> _logger;
    private readonly JwtSettings _jwtSettings;
    private readonly ITokenService _tokenService;

    public AuthController(
        UserManager<UsuarioDTO> userManager,
        ILogger<AuthController> logger,
        IOptions<JwtSettings> jwtSettings,
        ITokenService tokenService)
    {
        _userManager = userManager;
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Efetua login e retorna tokens de acesso
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Tentativa de login com email não cadastrado: {Email}", request.Email);
            return Unauthorized("Credenciais inválidas");
        }

        if (!await _userManager.CheckPasswordAsync(user, request.Password))
        {
            _logger.LogWarning("Tentativa de login com senha incorreta para usuário {UserId}", user.Id);
            return Unauthorized("Credenciais inválidas");
        }

        // gera JWT + expiração segura
        var jwt = await _tokenService.GenerateJwtTokenAsync(user);

        // gera refresh token forte
        var refreshToken = _tokenService.GenerateRefreshToken();

        // persiste refresh token vinculado ao usuário
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("Login bem-sucedido para usuário {UserId}", user.Id);

        var secondsToExpire = (int)(jwt.ExpirationUtc - DateTime.UtcNow).TotalSeconds;

        return Ok(new AuthResponse
        {
            Token = jwt.Token,
            RefreshToken = refreshToken,
            ExpiresIn = secondsToExpire,
            ExpirationUtc = jwt.ExpirationUtc,
            ExpirationLocal = jwt.ExpirationUtc.ToLocalTime(),
            UserName = user.Nome ?? string.Empty,
            UserEmail = user.Email ?? string.Empty
        });
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
        // extrai o principal mesmo se o JWT tiver expirado
        ClaimsPrincipal principal;
        try
        {
            principal = _tokenService.GetPrincipalFromExpiredToken(request.Token);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Token JWT inválido ao tentar refresh");
            return Unauthorized("Token inválido");
        }

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized("Token inválido");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return Unauthorized("Usuário não encontrado");

        // valida refresh token
        if (user.RefreshToken != request.RefreshToken ||
            user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return Unauthorized("Refresh token inválido ou expirado");
        }

        // gera novo JWT
        var newJwt = await _tokenService.GenerateJwtTokenAsync(user);
        var newSecondsToExpire = (int)(newJwt.ExpirationUtc - DateTime.UtcNow).TotalSeconds;

        // opcionalmente rotaciona refresh token a cada uso
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryInDays);
        await _userManager.UpdateAsync(user);

        return Ok(new AuthResponse
        {
            Token = newJwt.Token,
            RefreshToken = newRefreshToken,
            ExpiresIn = newSecondsToExpire,
            ExpirationUtc = newJwt.ExpirationUtc,
            ExpirationLocal = newJwt.ExpirationUtc.ToLocalTime(),
            UserName = user.Nome ?? string.Empty,
            UserEmail = user.Email ?? string.Empty
        });
    }

    /// <summary>
    /// Revoga o refresh token atual do usuário logado
    /// </summary>
    [HttpPost("revoke-token")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeToken()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return Unauthorized();

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _userManager.UpdateAsync(user);

        return NoContent();
    }
}
