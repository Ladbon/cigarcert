namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents the response for setting up two-factor authentication.
    /// </summary>
    public class TwoFactorSetupResponseDto
    {
        /// <summary>
        /// The message indicating the status of the two-factor setup.
        /// </summary>
        public string Message { get; set; } = "";

        /// <summary>
        /// The QR code to be scanned by the authenticator app.
        /// </summary>
        public string QrCode { get; set; } = "";

        /// <summary>
        /// The secret key for the two-factor authentication.
        /// </summary>
        public string SecretKey { get; set; } = "";
    }
}