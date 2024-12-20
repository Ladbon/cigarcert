namespace CigarCertifierAPI.Models
{
    public class BlacklistedToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = default!;
        public required DateTime ExpiresAt { get; set; }
    }
}
