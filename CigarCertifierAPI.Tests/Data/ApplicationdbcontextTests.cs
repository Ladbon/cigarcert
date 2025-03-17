using CigarCertifierAPI.Data;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CigarCertifierAPI.Tests.Data
{
    public class ApplicationDbContextTests
    {
        private DbContextOptions<ApplicationDbContext> CreateInMemoryOptions()
        {
            return new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: "TestDb")
                .Options;
        }

        [Fact]
        public async Task CanInsertUser()
        {
            using var context = new ApplicationDbContext(CreateInMemoryOptions());
            User user = new() { Username = "testuser", Email = "test@example.com", PasswordHash = "hashedpwd" };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            Assert.Equal(1, await context.Users.CountAsync());
            Assert.Equal("testuser", (await context.Users.FirstAsync()).Username);
        }

        [Fact]
        public async Task CanSaveAndRetrieveActiveTokenWithExpiry()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateInMemoryOptions();
            using var context = new ApplicationDbContext(options);

            ActiveToken activeToken = new()
            {
                Token = "testtoken",
                UserId = 1,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15)
            };

            // Act
            context.ActiveTokens.Add(activeToken);
            await context.SaveChangesAsync();

            // Assert
            ActiveToken retrievedToken = await context.ActiveTokens.FirstOrDefaultAsync();
            Assert.NotNull(retrievedToken);
            Assert.Equal(activeToken.Token, retrievedToken.Token);
            Assert.Equal(activeToken.ExpiresAt, retrievedToken.ExpiresAt);
        }
    }
}
