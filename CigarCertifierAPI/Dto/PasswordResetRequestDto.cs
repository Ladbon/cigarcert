namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to request a password reset.
    /// </summary>
    public class PasswordResetRequestDto
    {
        /// <summary>
        /// The email address associated with the user's account.
        /// </summary>
        public required string Email { get; set; }
    }
}