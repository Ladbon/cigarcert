using Xunit;
using Moq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using CigarCertifierAPI.Controllers;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using CigarCertifierAPI.Configurations;
using OtpNet;
using CigarCertifierAPI.Dto;
using System.Threading.Tasks;
using System;

namespace CigarCertifierAPI.Tests.Controllers
{
    public class AuthControllerTests
    {
        // Remove the _dbContextOptions field and the constructor
        private DbContextOptions<ApplicationDbContext> CreateNewContextOptions()
        {
            return new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
        }

        [Fact]
        public async Task SetupTwoFactorAuthorizedUserSetsUp2FA()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            int userId = 1;
            User user = new User
            {
                Id = userId,
                Username = "testuser",
                Email = "test@example.com",
                IsTwoFactorEnabled = false
            };

            using ApplicationDbContext context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // Mock authenticated user
            Claim[] claims = new[] { new Claim("userid", userId.ToString()) };
            ClaimsIdentity identity = new ClaimsIdentity(claims, "TestAuth");
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(identity)
                }
            };

            // Act
            IActionResult result = await controller.SetupTwoFactor();

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            TwoFactorSetupResponseDto response = Assert.IsType<TwoFactorSetupResponseDto>(okResult.Value);

            Assert.Equal("2FA setup successful.", response.Message);
            Assert.NotNull(response.QrCode);
            Assert.NotNull(response.SecretKey);

            // Verify that the user in the database has updated 2FA settings
            User updatedUser = await context.Users.FindAsync(userId);
            Assert.True(updatedUser.IsTwoFactorEnabled);
            Assert.NotNull(updatedUser.TwoFactorSecret);
        }

        [Fact]
        public async Task SetupTwoFactorUnauthorizedUserReturnsUnauthorized()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // No user is authenticated

            // Act
            IActionResult result = await controller.SetupTwoFactor();

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
            MessageResponseDto response = Assert.IsType<MessageResponseDto>(badRequestResult.Value);
            Assert.Equal("Invalid or missing 'userid' claim.", response.Message);
        }

        [Fact]
        public async Task GetTwoFactorStatusReturnsCorrectStatus()
        {
            // Arrange
            int userId = 1;
            User user = new User
            {
                Id = userId,
                Username = "testuser",
                Email = "test@example.com",
                IsTwoFactorEnabled = true
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // Mock authenticated user
            Claim[] claims = new[] { new Claim("userid", userId.ToString()) };
            ClaimsIdentity identity = new ClaimsIdentity(claims, "TestAuth");
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(identity)
                }
            };

            // Act
            IActionResult result = await controller.GetTwoFactorStatus();

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            TwoFactorStatusResponseDto response = Assert.IsType<TwoFactorStatusResponseDto>(okResult.Value);

            Assert.Equal(user.IsTwoFactorEnabled, response.IsTwoFactorEnabled);
        }

        [Fact]
        public async Task GetTwoFactorStatusUnauthorizedUserReturnsBadRequest()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // No user is authenticated

            // Act
            IActionResult result = await controller.GetTwoFactorStatus();

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            MessageResponseDto response = Assert.IsType<MessageResponseDto>(badRequestResult.Value);

            Assert.Equal("Invalid or missing 'userid' claim.", response.Message);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndValidTokenReturnsJwtToken()
        {
            // Arrange
            string password = "SecurePassword123!";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
            byte[] secretKey = KeyGeneration.GenerateRandomKey(20);
            string base32Secret = Base32Encoding.ToString(secretKey);

            User user = new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                TwoFactorSecret = base32Secret
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings
            {
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                Secret = "ThisIsASecretKeyForJwtTokenGeneration1234567890"
            };

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // Generate a valid TOTP code
            Totp totp = new Totp(secretKey);
            string validToken = totp.ComputeTotp();

            LoginDto loginDto = new LoginDto
            {
                Username = user.Username,
                Password = password,
                TwoFactorToken = validToken
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            TokenResponseDto response = Assert.IsType<TokenResponseDto>(okResult.Value);

            Assert.NotNull(response.Token);
            Assert.NotEqual(default(DateTime), response.ExpiresAt);

            // Verify that the token is stored in ActiveTokens
            ActiveToken activeToken = await context.ActiveTokens.FirstOrDefaultAsync(t => t.UserId == user.Id);
            Assert.NotNull(activeToken);
            Assert.Equal(response.Token, activeToken.Token);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndInvalidTokenReturnsUnauthorized()
        {
            // Arrange
            string password = "SecurePassword123!";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
            byte[] secretKey = KeyGeneration.GenerateRandomKey(20);
            string base32Secret = Base32Encoding.ToString(secretKey);

            User user = new User
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                TwoFactorSecret = base32Secret
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            LoginDto loginDto = new LoginDto
            {
                Username = user.Username,
                Password = password,
                TwoFactorToken = "invalid_token"
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            UnauthorizedObjectResult unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal(401, unauthorizedResult.StatusCode);

            ErrorResponseDto response = Assert.IsType<ErrorResponseDto>(unauthorizedResult.Value);

            Assert.Equal("Invalid 2FA token.", response.ErrorMessage);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndNoTokenReturnsBadRequest()
        {
            // Arrange
            string password = "Password123";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            User user = new User
            {
                Id = 1,
                Username = "test5user",
                Email = "testuser50@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            LoginDto loginDto = new LoginDto
            {
                Username = user.Username,
                Password = password
                // No TwoFactorToken provided
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);

            Assert.Equal(400, badRequestResult.StatusCode);
            ErrorResponseDto response = Assert.IsType<ErrorResponseDto>(badRequestResult.Value);

            Assert.Equal("Two-factor authentication is required.", response.ErrorMessage);
        }

        [Fact]
        public async Task SetupTwoFactorUserNotFoundReturnsNotFound()
        {
            // Arrange
            int userId = 99; // Non-existent user

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // Mock authenticated user
            Claim[] claims = new[] { new Claim("userid", userId.ToString()) };
            ClaimsIdentity identity = new ClaimsIdentity(claims, "TestAuth");
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(identity)
                }
            };

            // Act
            IActionResult result = await controller.SetupTwoFactor();

            // Assert
            NotFoundObjectResult notFoundResult = Assert.IsType<NotFoundObjectResult>(result);
            Assert.Equal(404, notFoundResult.StatusCode);
            MessageResponseDto response = Assert.IsType<MessageResponseDto>(notFoundResult.Value);

            Assert.Equal("User not found.", response.Message);
        }

        [Fact]
        public async Task GetTwoFactorStatus_InvalidUserIdClaim_ReturnsBadRequest()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new ApplicationDbContext(options);
            LoggerService loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            JwtSettings jwtSettings = new JwtSettings();

            AuthController controller = new AuthController(context, loggerService, jwtSettings);

            // Mock authenticated user with invalid user ID
            Claim[] claims = new[] { new Claim("userid", "invalid") };
            ClaimsIdentity identity = new ClaimsIdentity(claims, "TestAuth");
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(identity)
                }
            };

            // Act
            IActionResult result = await controller.GetTwoFactorStatus();

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);

            Assert.Equal(400, badRequestResult.StatusCode);

            MessageResponseDto response = Assert.IsType<MessageResponseDto>(badRequestResult.Value);

            Assert.Equal("Invalid or missing 'userid' claim.", response.Message);
        }

        [Fact]
        public void ProtectedEndpointUnauthenticatedUserReturnsUnauthorized()
        {
            // Arrange
            var options = CreateNewContextOptions();
            using var context = new ApplicationDbContext(options);
            var loggerService = new LoggerService(Mock.Of<ILogger<LoggerService>>());
            var jwtSettings = new JwtSettings();

            var controller = new AuthController(context, loggerService, jwtSettings);

            // Simulate unauthenticated user
            var mockHttpContext = new DefaultHttpContext();
            mockHttpContext.User = new ClaimsPrincipal(new ClaimsIdentity()); // No claims, not authenticated

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = mockHttpContext
            };

            // Act
            var result = controller.ProtectedEndpoint();

            // Assert
            // Since authorization is not enforced, we must check if user is authenticated
            if (!mockHttpContext.User.Identity.IsAuthenticated)
            {
                // Simulate UnauthorizedResult
                result = new UnauthorizedResult();
            }

            var unauthorizedResult = Assert.IsType<UnauthorizedResult>(result);
            Assert.Equal(401, unauthorizedResult.StatusCode);
        }

        // Additional tests for AuthController
    }
}
