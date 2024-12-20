using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    public class LoginDto
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;

        public string? TwoFactorToken { get; set; }
    }
}
