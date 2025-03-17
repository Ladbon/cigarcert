using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CigarCertifierAPI.Configurations;
using CigarCertifierAPI.Models;
using Microsoft.IdentityModel.Tokens;

namespace CigarCertifierAPI.Utilities
{
    public static class JwtHelper
    {
        public static (string Token, DateTime Expiry) GenerateJwtToken(User user, JwtSettings settings)
        {
            // Validate the secret key length
            if (string.IsNullOrEmpty(settings.Secret) || Encoding.UTF8.GetByteCount(settings.Secret) < 32)
                throw new InvalidOperationException("JWT Secret must be at least 32 bytes (256 bits) long.");

            // Create the symmetric security key
            SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(settings.Secret));
            SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);

            // Define the JWT claims
            Claim[] claims =
            {
        new(JwtRegisteredClaimNames.Sub, user.Username),
        new(JwtRegisteredClaimNames.Email, user.Email),
        new("userid", user.Id.ToString()),
        new("unique_claim", Guid.NewGuid().ToString()) // Add a unique claim
    };

            // Set token expiry
            DateTime expiry = DateTime.UtcNow.AddMinutes(15);

            // Create the JWT
            JwtSecurityToken token = new(
                issuer: settings.Issuer,
                audience: settings.Audience,
                claims: claims,
                expires: expiry,
                signingCredentials: creds);

            string tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return (tokenString, expiry);
        }

        public static int? GetUserIdFromClaims(ClaimsPrincipal user)
        {
            if (user?.Identity == null || !user.Identity.IsAuthenticated)
            {
                return null;
            }

            var userIdClaim = user.Claims.FirstOrDefault(c => c.Type == "userid");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int userId))
            {
                return null;
            }

            return userId;
        }

        public static string GetJwtSecret(IConfiguration configuration)
        {
            // Prioritize the environment variable
            string? secretKeyFromEnv = Environment.GetEnvironmentVariable("JWT_SECRET");
            if (!string.IsNullOrEmpty(secretKeyFromEnv))
            {
                return secretKeyFromEnv;
            }

            // Fallback to configuration
            string? secretKeyFromConfig = configuration["Jwt:Secret"];
            if (!string.IsNullOrEmpty(secretKeyFromConfig))
            {
                return secretKeyFromConfig;
            }

            // If neither is set, throw an exception
            throw new InvalidOperationException("JWT SecretKey is not configured.");
        }
    }
}
