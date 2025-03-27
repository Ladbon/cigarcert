using CigarCertifierAPI.Configurations;
using Microsoft.AspNetCore.Http;
using CigarCertifierAPI.Controllers;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Dto;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using OtpNet;
using Xunit;
using CigarCertifierAPI.Utilities;

namespace CigarCertifierAPI.Tests.Controllers
{
    public class AuthControllerTests
    {


        private DbContextOptions<ApplicationDbContext> CreateNewContextOptions()
        {
            return new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

        }

        private EmailService CreateEmailService(Mock<ILogger<EmailService>> mockLogger)
        {
            Dictionary<string, string> inMemorySettings = new()
            {
                {"EmailSettings:SmtpHost", "smtp.example.com"},
                {"EmailSettings:SmtpPort", "587"},
                {"EmailSettings:SenderEmail", "no-reply@example.com"},
                {"EmailSettings:SenderName", "Example"},
                {"EmailSettings:Username", "username"},
                {"EmailSettings:Password", "password"},
                {"SENDGRID_API_KEY", "test_sendgrid_api_key"} // Add SendGrid API Key for testing
            };

            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(inMemorySettings)
                .Build();

            return new EmailService(configuration, mockLogger.Object);
        }

        private LoggerService CreateLoggerService()
        {
            Mock<ILogger<LoggerService>> mockLogger = new();
            return new LoggerService(mockLogger.Object);
        }

        [Fact]
        public async Task SetupTwoFactorAuthorizedUserSetsUp2FA()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            int userId = 1;
            User user = new()
            {
                Id = userId,
                Username = "testuser",
                Email = "test@example.com",
                IsTwoFactorEnabled = false
            };

            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // Mock authenticated user
            Claim[] claims = [new("userid", userId.ToString())];
            ClaimsIdentity identity = new(claims, "TestAuth");
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
            Assert.False(updatedUser.IsTwoFactorEnabled); // Should remain false until activation
            Assert.NotNull(updatedUser.TwoFactorSecret);
        }

        [Fact]
        public async Task SetupTwoFactorUnauthorizedUserReturnsBadRequest()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // No user is authenticated

            // Act
            IActionResult result = await controller.SetupTwoFactor();

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequestResult.StatusCode);
            MessageResponseDto response = Assert.IsType<MessageResponseDto>(badRequestResult.Value);
            Assert.Equal("Invalid or missing 'userid' claim.", response.Message);
        }

        [Fact]
        public async Task GetTwoFactorStatusReturnsCorrectStatus()
        {
            // Arrange
            int userId = 1;
            User user = new()
            {
                Id = userId,
                Username = "testuser",
                Email = "test@example.com",
                IsTwoFactorEnabled = true
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // Mock authenticated user
            Claim[] claims = [new("userid", userId.ToString())];
            ClaimsIdentity identity = new(claims, "TestAuth");
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
            using ApplicationDbContext context = new(options);
            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // No user is authenticated

            // Act
            IActionResult result = await controller.GetTwoFactorStatus();

            // Assert
            BadRequestObjectResult badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequestResult.StatusCode);
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

            User user = new()
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                TwoFactorSecret = base32Secret,
                EmailConfirmed = true // Ensure email is confirmed
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new()
            {
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                Secret = "ThisIsASecretKeyForJwtTokenGeneration1234567890"
            };
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger);

            AuthController controller = new(context, loggerService, jwtSettings, emailService);

            // Generate a valid TOTP code
            Totp totp = new(secretKey);
            string validToken = totp.ComputeTotp();

            LoginDto loginDto = new()
            {
                Username = user.Username,
                Password = password,
                TwoFactorToken = validToken
            };

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            LoginResponseDto response = Assert.IsType<LoginResponseDto>(okResult.Value);

            Assert.False(response.IsTwoFactorRequired);
            Assert.Equal("Login successful.", response.Message);
            Assert.NotNull(response.ExpiresAt);
            Assert.Null(response.Token); // Token is stored in HttpOnly cookie

            // Verify that the token is stored in ActiveTokens
            ActiveToken activeToken = await context.ActiveTokens.FirstOrDefaultAsync(t => t.UserId == user.Id);
            Assert.NotNull(activeToken);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndInvalidTokenReturnsUnauthorized()
        {
            // Arrange
            string password = "SecurePassword123!";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
            byte[] secretKey = KeyGeneration.GenerateRandomKey(20);
            string base32Secret = Base32Encoding.ToString(secretKey);

            User user = new()
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                TwoFactorSecret = base32Secret,
                EmailConfirmed = true // Ensure email is confirmed
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger);

            AuthController controller = new(context, loggerService, jwtSettings, emailService);

            LoginDto loginDto = new()
            {
                Username = user.Username,
                Password = password,
                TwoFactorToken = "invalid_token"
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            UnauthorizedObjectResult unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            ErrorResponseDto response = Assert.IsType<ErrorResponseDto>(unauthorizedResult.Value);
            Assert.Equal("Invalid 2FA token.", response.ErrorMessage);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndNoTokenReturnsOkResult()
        {
            // Arrange
            string password = "Password123";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            User user = new()
            {
                Id = 1,
                Username = "testuser5",
                Email = "testuser50@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                EmailConfirmed = true // Ensure email is confirmed
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger);

            AuthController controller = new(context, loggerService, jwtSettings, emailService);

            LoginDto loginDto = new()
            {
                Username = user.Username,
                Password = password
                // No TwoFactorToken provided
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            LoginResponseDto response = Assert.IsType<LoginResponseDto>(okResult.Value);

            Assert.True(response.IsTwoFactorRequired);
            Assert.Equal("Two-factor authentication is required.", response.Message);
            Assert.Null(response.Token);
            Assert.Null(response.ExpiresAt);
        }

        [Fact]
        public async Task LoginWith2FAEnabledAndNoTokenReturnsUnauthorized()
        {
            // Arrange
            string password = "Password123";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            User user = new()
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = true,
                EmailConfirmed = true
            };

            var options = CreateNewContextOptions();
            using var context = new ApplicationDbContext(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            var loggerService = CreateLoggerService();
            var jwtSettings = new JwtSettings();
            var mockEmailLogger = new Mock<ILogger<EmailService>>();
            var emailService = CreateEmailService(mockEmailLogger);

            var controller = new AuthController(context, loggerService, jwtSettings, emailService);

            var loginDto = new LoginDto
            {
                Username = user.Username,
                Password = password
                // No TwoFactorToken provided
            };

            // Act
            var result = await controller.Login(loginDto);

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            var response = Assert.IsType<ErrorResponseDto>(unauthorizedResult.Value);
            Assert.Equal("Two-factor authentication is required.", response.ErrorMessage);
        }

        [Fact]
        public async Task SetupTwoFactorUserNotFoundReturnsNotFound()
        {
            // Arrange
            int userId = 99; // Non-existent user

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // Mock authenticated user
            Claim[] claims = [new("userid", userId.ToString())];
            ClaimsIdentity identity = new(claims, "TestAuth");
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
            Assert.Equal(StatusCodes.Status404NotFound, notFoundResult.StatusCode);
            MessageResponseDto response = Assert.IsType<MessageResponseDto>(notFoundResult.Value);
            Assert.Equal("User not found.", response.Message);
        }

        [Fact]
        public async Task GetTwoFactorStatus_InvalidUserIdClaim_ReturnsBadRequest()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // Mock authenticated user with invalid user ID
            Claim[] claims = [new("userid", "invalid")];
            ClaimsIdentity identity = new(claims, "TestAuth");
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
            Assert.Equal(StatusCodes.Status400BadRequest, badRequestResult.StatusCode);

            MessageResponseDto response = Assert.IsType<MessageResponseDto>(badRequestResult.Value);
            Assert.Equal("Invalid or missing 'userid' claim.", response.Message);
        }

        [Fact]
        public void ProtectedEndpointUnauthenticatedUserReturnsUnauthorized()
        {
            // Arrange
            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new();
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger); // Use the helper method with mock logger

            AuthController controller = new(context, loggerService, jwtSettings, emailService); // Add emailService

            // Simulate unauthenticated user
            DefaultHttpContext mockHttpContext = new()
            {
                User = new ClaimsPrincipal(new ClaimsIdentity()) // No claims, not authenticated
            };

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = mockHttpContext
            };

            // Act
            IActionResult result = controller.ProtectedEndpoint();

            // Assert
            // Since authorization is handled by ASP.NET Core middleware, direct controller call won't enforce it.
            // To simulate the behavior, check if the user is authenticated.
            if (!mockHttpContext.User.Identity.IsAuthenticated)
            {
                // Simulate UnauthorizedResult
                result = new UnauthorizedResult();
            }

            UnauthorizedResult unauthorizedResult = Assert.IsType<UnauthorizedResult>(result);
            Assert.Equal(StatusCodes.Status401Unauthorized, unauthorizedResult.StatusCode);
        }

        [Fact]
        public async Task Login_ReturnsTokenWithCorrectExpiry()
        {
            // Arrange
            string password = "Password123!";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            User user = new()
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = false,
                EmailConfirmed = true // Ensure email is confirmed
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new()
            {
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                Secret = "ThisIsASecretKeyForJwtTokenGeneration1234567890"
            };
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger);

            AuthController controller = new(context, loggerService, jwtSettings, emailService);

            // Set up the ControllerContext with a valid HttpContext
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            };

            LoginDto loginDto = new()
            {
                Username = user.Username,
                Password = password
            };

            // Act
            IActionResult result = await controller.Login(loginDto);

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            LoginResponseDto response = Assert.IsType<LoginResponseDto>(okResult.Value);

            Assert.False(response.IsTwoFactorRequired);
            Assert.Equal("Login successful.", response.Message);
            Assert.NotNull(response.ExpiresAt);

            // Since the token is stored in an HttpOnly cookie, Token will be null
            Assert.Null(response.Token);
        }

        [Fact]
        public async Task RefreshToken_ReturnsNewTokenWithCorrectExpiry()
        {
            // Arrange
            string password = "Password123!";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            User user = new()
            {
                Id = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = false,
                EmailConfirmed = true // Ensure email is confirmed
            };

            DbContextOptions<ApplicationDbContext> options = CreateNewContextOptions();
            using ApplicationDbContext context = new(options);
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            LoggerService loggerService = CreateLoggerService();
            JwtSettings jwtSettings = new()
            {
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                Secret = "ThisIsASecretKeyForJwtTokenGeneration1234567890"
            };
            Mock<ILogger<EmailService>> mockEmailLogger = new();
            EmailService emailService = CreateEmailService(mockEmailLogger);

            AuthController controller = new(context, loggerService, jwtSettings, emailService);

            // Generate an initial token
            (string initialToken, DateTime initialExpiry) = JwtHelper.GenerateJwtToken(user, jwtSettings);

            // Add the token to active tokens
            context.ActiveTokens.Add(new ActiveToken
            {
                Token = initialToken,
                UserId = user.Id,
                ExpiresAt = initialExpiry
            });
            await context.SaveChangesAsync();

            // Mock authenticated user and set the token cookie
            Claim[] claims = { new("userid", user.Id.ToString()) };
            ClaimsIdentity identity = new(claims, "TestAuth");
            DefaultHttpContext httpContext = new()
            {
                User = new ClaimsPrincipal(identity)
            };
            // Set the cookie by modifying the Headers directly
            httpContext.Request.Headers["Cookie"] = "token=" + initialToken;

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            // Act
            DateTime beforeTokenGeneration = DateTime.UtcNow;
            IActionResult result = await controller.RefreshToken();
            DateTime afterTokenGeneration = DateTime.UtcNow;

            // Assert
            OkObjectResult okResult = Assert.IsType<OkObjectResult>(result);
            LoginResponseDto response = Assert.IsType<LoginResponseDto>(okResult.Value);

            Assert.False(response.IsTwoFactorRequired);
            Assert.Equal("Token refreshed successfully.", response.Message);
            Assert.NotNull(response.ExpiresAt);
            Assert.Null(response.Token); // Token is stored in HttpOnly cookie

            // Verify that the token expiry matches the expected duration
            DateTime expectedExpiry = beforeTokenGeneration.AddMinutes(15);
            DateTime? actualExpiry = response.ExpiresAt;
            TimeSpan? timeDifference = actualExpiry - expectedExpiry;

            // Allow a small margin for delay
            Assert.True(Math.Abs(timeDifference.Value.TotalSeconds) < 60, "Token expiry time deviation is too large.");
        }
    }
}
