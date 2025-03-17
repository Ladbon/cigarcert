namespace CigarCertifierAPI.Utilities
{
    public static class PasswordHelper
    {
        public static string HashPassword(string plainPassword)
        {
            return BCrypt.Net.BCrypt.HashPassword(plainPassword);
        }

        public static bool VerifyPassword(string password, string passwordHash)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, passwordHash);
            }
            catch (Exception ex)
            {
                // Log the exception but don't crash
                Console.Error.WriteLine($"Error verifying password: {ex.Message}");
                return false;
            }
        }
    }
}
