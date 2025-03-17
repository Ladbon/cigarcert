using System.Threading.Tasks;
using System;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace CigarCertifierAPI.Tests.Services
{
    public class TokenCleanupServiceTests
    {
        [Fact]
        public async Task TokenCleanupService_RemovesExpiredTokens()
        {
            // Arrange
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: "TestDatabase")
                .Options;

            var context = new ApplicationDbContext(options);
            var loggerMock = new Mock<ILogger<TokenCleanupService>>();

            // Seed the database with test data
            context.BlacklistedTokens.Add(new BlacklistedToken { Token = "expiredToken1", ExpiresAt = DateTime.UtcNow.AddDays(-1) });
            context.ActiveTokens.Add(new ActiveToken { Token = "expiredToken2", ExpiresAt = DateTime.UtcNow.AddDays(-1) });
            await context.SaveChangesAsync();

            var service = new TokenCleanupService(context, loggerMock.Object);

            // Act
            await service.CleanupExpiredTokensAsync();

            // Assert
            Assert.Empty(context.BlacklistedTokens);
            Assert.Empty(context.ActiveTokens);
        }
    }
}
