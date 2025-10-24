using LPRIntelbrasDashboard.DTO;
using LPRIntelbrasDashboard.Models;
using System.Security.Claims;

public interface ITokenService
{
    Task<JwtResult> GenerateJwtTokenAsync(UsuarioDTO user);
    string GenerateRefreshToken();
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}
