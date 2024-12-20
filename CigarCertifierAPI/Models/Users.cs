namespace CigarCertifierAPI.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public bool IsTwoFactorEnabled { get; set; } = false;
        public string? TwoFactorSecret { get; set; } // For storing Google Authenticator secret key
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Fields for password reset
        public string? PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpiry { get; set; }
    }

}
