namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the response for two-factor authentication status.
    /// </summary>
    public class TwoFactorStatusResponseDto
    {
        /// <summary>
        /// Indicates whether two-factor authentication is enabled for the user.
        /// </summary>
        public bool IsTwoFactorEnabled { get; set; }
    }
}
