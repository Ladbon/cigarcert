namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the data required to reset a user's password.
    /// </summary>
    public class ResetPasswordDto
    {
        /// <summary>
        /// The token used to authorize the password reset.
        /// </summary>
        public required string Token { get; set; }

        /// <summary>
        /// The new password to be set for the user.
        /// </summary>
        public required string NewPassword { get; set; }
    }
}