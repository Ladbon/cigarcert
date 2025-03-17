// EmailConfirmationDto.cs
using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to confirm a user's email.
    /// </summary>
    public class EmailConfirmationDto
    {
        /// <summary>
        /// The email address of the user.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = default!;

        /// <summary>
        /// The confirmation code sent to the user's email.
        /// </summary>
        [Required]
        public string ConfirmationCode { get; set; } = default!;
    }
}
