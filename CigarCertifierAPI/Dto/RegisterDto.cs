// RegisterDto.cs
using System.ComponentModel.DataAnnotations;
using CigarCertifierAPI.Utilities;


namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to register a new user.
    /// </summary>
    public class RegisterDto
    {
        /// <summary>
        /// The username for the new user.
        /// </summary>
        [Required]
        [RegularExpression("^[a-zA-Z0-9]{4,20}$", ErrorMessage = "Username must be 4-20 alphanumeric characters.")]
        public string Username { get; set; } = default!;

        /// <summary>
        /// The email address of the new user.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = default!;

        /// <summary>
        /// The password for the new user.
        /// </summary>
        [Required]
        [PasswordValidation]
        public string Password { get; set; } = default!;
    }
}
