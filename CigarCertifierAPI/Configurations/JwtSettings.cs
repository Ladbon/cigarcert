using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Configurations
{
    public class JwtSettings
    {
        /// <summary>
        /// The issuer of the JWT.
        /// </summary>
        [Required]
        public string Issuer { get; set; } = string.Empty;

        /// <summary>
        /// The audience for the JWT.
        /// </summary>
        [Required]
        public string Audience { get; set; } = string.Empty;

        /// <summary>
        /// The secret key used to sign the JWT.
        /// </summary>
        [Required]
        [MinLength(32, ErrorMessage = "JWT Secret must be at least 32 characters long.")]
        public string Secret { get; set; } = string.Empty;
    }
}
