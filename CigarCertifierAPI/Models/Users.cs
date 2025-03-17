// User.cs
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace CigarCertifierAPI.Models
{
    /// <summary>
    /// Represents a user in the application.
    /// </summary>
    [Index(nameof(Email), IsUnique = true)]
    public class User
    {
        /// <summary>
        /// The unique identifier for the user.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The username of the user.
        /// </summary>
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// The email address of the user.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = default!;

        /// <summary>
        /// The hashed password of the user.
        /// </summary>
        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// Indicates whether two-factor authentication is enabled for the user.
        /// </summary>
        public bool IsTwoFactorEnabled { get; set; } = false;

        /// <summary>
        /// The secret key used for two-factor authentication.
        /// </summary>
        public string? TwoFactorSecret { get; set; }

        /// <summary>
        /// The date and time when the user was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// The token used to reset the user's password.
        /// </summary>
        public string? PasswordResetToken { get; set; }

        /// <summary>
        /// The expiration date and time of the password reset token.
        /// </summary>
        public DateTime? PasswordResetTokenExpiry { get; set; }

        /// <summary>
        /// Indicates whether the user's email has been confirmed.
        /// </summary>
        public bool EmailConfirmed { get; set; } = false;

        /// <summary>
        /// The code sent to the user's email for confirmation.
        /// </summary>
        public string? EmailConfirmationCode { get; set; }

        /// <summary>
        /// The expiration date and time of the email confirmation code.
        /// </summary>
        public DateTime? EmailConfirmationCodeExpiry { get; set; }

        /// <summary>
        /// The number of attempts made to confirm the user's email.
        /// </summary>
        public int EmailConfirmationAttempts { get; set; } = 0;

        /// <summary>
        /// The date and time when the last email confirmation was sent.
        /// </summary>
        public DateTime? LastEmailConfirmationSentAt { get; set; }
    }
}
