using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to register a new user.
    /// </summary>
    public class RegisterDto
    {
        /// <summary>
        /// The username of the new user.
        /// </summary>
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// The email address of the new user.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// The password for the new user.
        /// </summary>
        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string Password { get; set; } = string.Empty;
    }
}