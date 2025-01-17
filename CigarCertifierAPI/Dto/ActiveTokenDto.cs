using System.ComponentModel.DataAnnotations;

namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents an active JWT token associated with a user.
    /// </summary>
    public class ActiveTokenDto
    {
        /// <summary>
        /// The unique identifier of the active token.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The JWT token string.
        /// </summary>
        [Required]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// The user ID associated with this token.
        /// </summary>
        [Required]
        public int UserId { get; set; }

        /// <summary>
        /// The expiration date and time of the token.
        /// </summary>
        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}
