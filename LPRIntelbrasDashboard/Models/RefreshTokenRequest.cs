using System.ComponentModel.DataAnnotations;

namespace LPRIntelbrasDashboard.Models
{
    public class RefreshTokenRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string RefreshToken { get; set; }
    }
}
