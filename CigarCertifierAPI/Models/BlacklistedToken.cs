namespace CigarCertifierAPI.Models
{
    /// <summary>
    /// Represents a JWT token that has been blacklisted and should no longer be accepted.
    /// </summary>
    public class BlacklistedToken
    {
        /// <summary>
        /// The unique identifier of the blacklisted token.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The JWT token string.
        /// </summary>
        public string Token { get; set; } = default!;

        /// <summary>
        /// The expiration date and time of the token.
        /// </summary>
        public required DateTime ExpiresAt { get; set; }
    }
}
