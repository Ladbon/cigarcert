using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    public class ActiveTokenDto
    {
        public int Id { get; set; }

        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        public int UserId { get; set; }

        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}
