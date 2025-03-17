namespace CigarCertifierAPI.Dto
{
    public class LoginResponseDto
    {
        /// <summary>
        /// Indicates whether two-factor authentication is required.
        /// </summary>
        public bool IsTwoFactorRequired { get; set; }

        /// <summary>
        /// The JWT token, if issued.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// The expiration time of the token.
        /// </summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Profile information or messages.
        /// </summary>
        public string? Message { get; set; }
    }
}
