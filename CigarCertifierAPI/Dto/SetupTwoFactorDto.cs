namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to set up two-factor authentication for a user.
    /// </summary>
    public class SetupTwoFactorDto
    {
        /// <summary>
        /// The username of the user setting up two-factor authentication.
        /// </summary>
        public required string Username { get; set; }
    }
}