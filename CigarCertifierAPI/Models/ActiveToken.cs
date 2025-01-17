namespace CigarCertifierAPI.Models
{
    public class ActiveToken
    {
        public int Id { get; set; }
        public required string Token { get; set; }
        public int UserId { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}