namespace LPRIntelbrasDashboard.Models
{
    public class JwtResult
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpirationUtc { get; set; }
    }
}
