namespace CigarCertifierAPI.Dto
{
    /// <summary>
    /// Represents an error response with a message.
    /// </summary>
    public class ErrorResponseDto
    {
        /// <summary>
        /// The error message describing the issue.
        /// </summary>
        public string ErrorMessage { get; set; } = "";
    }
}