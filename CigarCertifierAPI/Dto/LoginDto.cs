using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required for a user to log in.
    /// </summary>
    public class LoginDto
    {
        /// <summary>
        /// The username of the user.
        /// </summary>
        [Required]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// The password of the user.
        /// </summary>
        [Required]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// The optional two-factor authentication token.
        /// </summary>
        public string? TwoFactorToken { get; set; }
    }
}
