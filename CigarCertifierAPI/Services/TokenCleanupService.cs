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
            List<Models.BlacklistedToken> expiredTokens = await _dbContext.BlacklistedTokens
                .Where(bt => bt.ExpiresAt < DateTime.UtcNow)
                .ToListAsync();

            _dbContext.BlacklistedTokens.RemoveRange(expiredTokens);
            int deletedCount = await _dbContext.SaveChangesAsync();

            _logger.LogInformation("{DeletedCount} expired tokens removed at {Time}", deletedCount, DateTime.UtcNow);
        }
    }
}