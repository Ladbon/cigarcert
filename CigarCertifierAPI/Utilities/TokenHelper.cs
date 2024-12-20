using System.IdentityModel.Tokens.Jwt;
using CigarCertifierAPI.Data;
using Microsoft.EntityFrameworkCore;

namespace CigarCertifierAPI.Utilities
{
    public static class TokenHelper
    {
        public static bool IsValidToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.CanReadToken(token);
        }
        public static async Task<bool> IsTokenValid(string token, ApplicationDbContext dbContext)
        {
            return IsValidToken(token) && !await IsTokenBlacklisted(token, dbContext);
        }

        public static DateTime? GetTokenExpiry(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var expiryUnix = jwtToken.Payload.Expiration;
            return expiryUnix.HasValue ? DateTimeOffset.FromUnixTimeSeconds(expiryUnix.Value).UtcDateTime : null;
        }

        public static bool IsTokenExpired(string token)
        {
            DateTime? expiry = GetTokenExpiry(token);
            return expiry == null || expiry <= DateTime.UtcNow;
        }

        public static async Task<bool> IsTokenBlacklisted(string token, ApplicationDbContext dbContext)
        {
            return await dbContext.BlacklistedTokens.AnyAsync(bt => bt.Token == token);
        }

    }
}
