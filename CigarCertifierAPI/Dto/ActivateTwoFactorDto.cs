// ActivateTwoFactorDto.cs
using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to activate two-factor authentication.
    /// </summary>
    public class ActivateTwoFactorDto
    {
        /// <summary>
        /// The verification code from the authenticator app.
        /// </summary>
        [Required]
        public string VerificationCode { get; set; } = string.Empty;
    }
}
