// PasswordValidationAttribute.cs
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace CigarCertifierAPI.Utilities
{
    /// <summary>
    /// Validates that a password meets complexity requirements.
    /// </summary>
    public class PasswordValidationAttribute : ValidationAttribute
    {
        private const string DefaultErrorMessage = "Password must be at least 8 characters and contain uppercase, lowercase, digit, and special character.";

        public PasswordValidationAttribute() : base(DefaultErrorMessage) { }

        public override bool IsValid(object? value)
        {
            if (value == null)
                return false;

            var password = value as string;
            if (string.IsNullOrEmpty(password))
                return false;

            var regex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$");
            return regex.IsMatch(password);
        }
    }
}
