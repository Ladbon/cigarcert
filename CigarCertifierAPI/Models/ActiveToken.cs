using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Models
{
    public class ActiveToken
    {
        public int Id { get; set; }

        [Required]
        public string Token { get; set; } = string.Empty;

        public int UserId { get; set; }

        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}
