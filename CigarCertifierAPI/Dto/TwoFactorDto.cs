namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required for two-factor authentication.
    /// </summary>
    public class TwoFactorDto
    {
        /// <summary>
        /// The username of the user.
        /// </summary>
        public required string Username { get; set; }

        /// <summary>
        /// The two-factor authentication token.
        /// </summary>
        public required string Token { get; set; }
    }
}