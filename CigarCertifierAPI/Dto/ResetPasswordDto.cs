// ResetPasswordDto.cs
using System.ComponentModel.DataAnnotations;
using CigarCertifierAPI.Utilities;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to reset a user's password.
    /// </summary>
    public class ResetPasswordDto
    {
        /// <summary>
        /// The token used to authorize the password reset.
        /// </summary>
        [Required]
        public string Token { get; set; } = default!;

        /// <summary>
        /// The new password to be set for the user.
        /// </summary>
        [Required]
        [PasswordValidation]
        public string NewPassword { get; set; } = default!;
    }
}
