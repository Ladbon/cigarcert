using CigarCertifierAPI.Data;
using Microsoft.EntityFrameworkCore;

namespace CigarCertifierAPI.Services
{
    public class TokenCleanupService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<TokenCleanupService> _logger;

        public TokenCleanupService(ApplicationDbContext dbContext, ILogger<TokenCleanupService> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task CleanupExpiredTokensAsync()
        {
            var now = DateTime.UtcNow;

            // Remove expired blacklisted tokens
            var expiredBlacklistedTokens = await _dbContext.BlacklistedTokens
                .Where(bt => bt.ExpiresAt <= now)
                .ToListAsync();

            if (expiredBlacklistedTokens.Count > 0)
            {
                _dbContext.BlacklistedTokens.RemoveRange(expiredBlacklistedTokens);
                _logger.LogInformation("{Count} expired blacklisted tokens removed at {Time}", expiredBlacklistedTokens.Count, now);
            }

            // Remove expired active tokens
            var expiredActiveTokens = await _dbContext.ActiveTokens
                .Where(at => at.ExpiresAt <= now)
                .ToListAsync();

            if (expiredActiveTokens.Count > 0)
            {
                _dbContext.ActiveTokens.RemoveRange(expiredActiveTokens);
                _logger.LogInformation("{Count} expired active tokens removed at {Time}", expiredActiveTokens.Count, now);
            }

            // Save changes if any tokens were removed
            if (expiredBlacklistedTokens.Count > 0 || expiredActiveTokens.Count > 0)
            {
                await _dbContext.SaveChangesAsync();
            }
        }
    }
}