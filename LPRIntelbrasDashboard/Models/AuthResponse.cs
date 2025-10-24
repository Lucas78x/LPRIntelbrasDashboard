namespace LPRIntelbrasDashboard.Models
{
    public class AuthResponse
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresIn { get; set; } 
        public DateTime ExpirationUtc { get; set; }
        public DateTime ExpirationLocal { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string UserEmail { get; set; } = string.Empty;
    }


}
