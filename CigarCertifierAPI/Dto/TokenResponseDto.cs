namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the response containing a JWT token.
    /// </summary>
    public class TokenResponseDto
    {
        /// <summary>
        /// A message indicating the result of the token generation.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// The generated JWT token.
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// The expiration date and time of the token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
}
