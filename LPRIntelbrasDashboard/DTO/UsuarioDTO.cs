using Microsoft.AspNetCore.Identity;

namespace LPRIntelbrasDashboard.DTO
{
    public class UsuarioDTO : IdentityUser<int> 
    {
        public string Nome { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public ICollection<Alerta> Alertas { get; set; } = new List<Alerta>();
    }

}
