using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Models
{
    /// <summary>
    /// Represents a JWT token that has been blacklisted and should no longer be accepted.
    /// </summary>
    public class BlacklistedToken
    {
        public int Id { get; set; }

        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}
