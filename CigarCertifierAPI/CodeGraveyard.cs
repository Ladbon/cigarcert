
/*using CigarCertifierAPI.Data;
using CigarCertifierAPI.Services;
using Hangfire;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

        // Add logging configuration
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddDebug();

        IServiceCollection services = builder.Services;
        ConfigurationManager configuration = builder.Configuration;

        // Add Hangfire services
        services.AddHangfire(config => config
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseSqlServerStorage(configuration.GetConnectionString("DefaultConnection")));

        services.AddHangfireServer();

        // Add Controllers
        services.AddControllers();

        // Configure EF Core
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

        // JWT Configuration
        IConfigurationSection jwtSettings = configuration.GetSection("Jwt");
        string? secretKeyEnv = Environment.GetEnvironmentVariable("JWT_SECRET");
        if (string.IsNullOrEmpty(secretKeyEnv))
            secretKeyEnv = "xe^z@;Su&W2?3_X4w~q:-Ka<nCjGk+hE8";
           // throw new InvalidOperationException("JWT SecretKey is not configured. Set the 'JWT_SECRET' environment variable.");

        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(secretKeyEnv));

        // Add Authentication
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["Issuer"],
                    ValidAudience = jwtSettings["Audience"],
                    IssuerSigningKey = key
                };

                // Custom token validation for blacklist
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        var dbContext = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();

                        if (context.SecurityToken is JsonWebToken jsonWebToken)
                        {
                            string token = jsonWebToken.EncodedToken;
                            bool isBlacklisted = await dbContext.BlacklistedTokens.AnyAsync(bt => bt.Token == token);

                            logger.LogInformation("Token validated. Is blacklisted: {IsBlacklisted}", isBlacklisted);

                            if (isBlacklisted)
                            {
                                logger.LogWarning("Token is blacklisted: {Token}", token);
                                context.Fail("This token has been revoked.");
                            }
                        }
                        else
                        {
                            logger.LogWarning("Security token is not a valid JsonWebToken.");
                            context.Fail("Invalid token type.");
                        }
                    }
                };
            });

        services.AddAuthorization();

        // Register TokenCleanupService
        services.AddScoped<TokenCleanupService>();
        // Register LoggerService
        services.AddScoped<LoggerService>();

        WebApplication app = builder.Build();

        // Hangfire Dashboard
        app.UseHangfireDashboard(); // Optional, for job monitoring

        // Schedule cleanup job
        RecurringJob.AddOrUpdate<TokenCleanupService>(
            "CleanupExpiredTokens",
            service => service.CleanupExpiredTokens(),
            Cron.Hourly); // Adjust as needed

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        app.Run();
    }

    // Token cleanup job
    public class TokenCleanupService(ApplicationDbContext dbContext, ILogger<Program.TokenCleanupService> logger)
    {
        private readonly ApplicationDbContext _dbContext = dbContext;
        private readonly ILogger<TokenCleanupService> _logger = logger;

        public void CleanupExpiredTokens()
        {
            var expiredTokens = _dbContext.BlacklistedTokens
                .Where(bt => bt.ExpiresAt < DateTime.UtcNow);

            int deletedCount = expiredTokens.Count();
            _dbContext.BlacklistedTokens.RemoveRange(expiredTokens);
            _dbContext.SaveChanges();

            _logger.LogInformation("{DeletedCount} expired tokens removed at {Time}", deletedCount, DateTime.UtcNow);
        }
    }
}
*/





/*using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Dto;
using CigarCertifierAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using QRCoder;

namespace CigarCertifierAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(ApplicationDbContext dbContext, IConfiguration configuration, ILogger<AuthController> logger) : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext = dbContext;
        private readonly IConfiguration _configuration = configuration;
        private readonly ILogger<AuthController> _logger = logger;

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            _logger.LogInformation("Attempting to register a new user: {Username}", model.Username);

            if (await _dbContext.Users.AnyAsync(u => u.Username == model.Username))
            {
                _logger.LogWarning("Username {Username} is already taken", model.Username);
                return BadRequest("Username is already taken");
            }

            string passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);

            User user = new()
            {
                Username = model.Username,
                Email = model.Email,
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = false
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("User {Username} registered successfully", model.Username);
            return Ok("User registered successfully!");
        }


        [Authorize]
        [HttpPatch("setup-2fa")]
        public async Task<IActionResult> SetupTwoFactor()
        {
            string? userIdClaim = User.FindFirst("userid")?.Value;

            if (string.IsNullOrWhiteSpace(userIdClaim) || !int.TryParse(userIdClaim, out int userId))
            {
                _logger.LogWarning("Setup 2FA failed. Invalid or missing user ID claim.");
                return BadRequest("Invalid user ID.");
            }

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
            {
                _logger.LogWarning("Setup 2FA failed. User not found for ID: {UserId}", userId);
                return NotFound("User not found.");
            }

            byte[] newSecretKey = KeyGeneration.GenerateRandomKey(20);
            user.TwoFactorSecret = Base32Encoding.ToString(newSecretKey);
            user.IsTwoFactorEnabled = true;
            await _dbContext.SaveChangesAsync();

            string qrCodeUrl = GenerateQrCodeUrl(user.Email, user.TwoFactorSecret);
            string qrCodeBase64 = GenerateQrCodeBase64(qrCodeUrl);

            _logger.LogInformation("2FA setup successful for user ID: {UserId}", userId);

            return Ok(new
            {
                message = "2FA setup successful.",
                qrCode = $"data:image/png;base64,{qrCodeBase64}",
                secretKey = user.TwoFactorSecret
            });
        }

        [Authorize]
        [HttpGet("2fa-status")]
        public async Task<IActionResult> GetTwoFactorStatus()
        {
            string? userIdClaim = User.FindFirst("userid")?.Value;

            if (string.IsNullOrWhiteSpace(userIdClaim) || !int.TryParse(userIdClaim, out int userId))
            {
                _logger.LogWarning("2FA status check failed. Invalid or missing user ID claim.");
                return BadRequest("Invalid user ID.");
            }

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null)
            {
                _logger.LogWarning("2FA status check failed. User not found for ID: {UserId}", userId);
                return NotFound("User not found.");
            }

            _logger.LogInformation("2FA status retrieved for user ID: {UserId}", userId);
            return Ok(new { isTwoFactorEnabled = user.IsTwoFactorEnabled });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            _logger.LogInformation("Attempting to log in user: {Username}", model.Username);

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed for user: {Username}. Invalid credentials.", model.Username);
                return Unauthorized("Invalid username or password.");
            }

            if (user.IsTwoFactorEnabled && string.IsNullOrWhiteSpace(model.TwoFactorToken))
            {
                _logger.LogWarning("Login failed. 2FA token not provided for user: {Username}", model.Username);
                return BadRequest("Two-factor authentication is required.");
            }

            if (user.IsTwoFactorEnabled)
            {
                Totp totp = new(Base32Encoding.ToBytes(user.TwoFactorSecret));
                if (!totp.VerifyTotp(model.TwoFactorToken, out _))
                {
                    _logger.LogWarning("Login failed. Invalid 2FA token for user: {Username}", model.Username);
                    return Unauthorized("Invalid 2FA token.");
                }
            }

            (string token, DateTime expiry) = GenerateJwtToken(user);
            _logger.LogInformation("User {Username} logged in successfully", model.Username);

            return Ok(new { Token = token, ExpiresAt = expiry });
        }

        [Authorize]
        [HttpDelete("logout")]
        public async Task<IActionResult> Logout()
        {
            string? token = HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Split(" ").Last();

            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Logout failed. No token provided in Authorization header.");
                return BadRequest("No token provided.");
            }

            var jwtHandler = new JwtSecurityTokenHandler();
            if (!jwtHandler.CanReadToken(token))
            {
                _logger.LogWarning("Logout failed. Invalid token format.");
                return BadRequest("Invalid token format.");
            }

            var jwtToken = jwtHandler.ReadJwtToken(token);
            var expiryUnix = jwtToken.Payload.Expiration;
            if (!expiryUnix.HasValue)
            {
                _logger.LogWarning("Logout failed. Token does not have an expiry.");
                return BadRequest("Token does not have an expiry.");
            }

            DateTime expiryDate = DateTimeOffset.FromUnixTimeSeconds(expiryUnix.Value).UtcDateTime;

            BlacklistedToken blacklistedToken = new()
            {
                Token = token,
                ExpiresAt = expiryDate
            };

            _dbContext.BlacklistedTokens.Add(blacklistedToken);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Token blacklisted and user logged out.");
            return Ok("You have been logged out.");
        }

        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            _logger.LogInformation("Access granted to protected endpoint.");
            return Ok("You have accessed a protected endpoint!");
        }

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto model)
        {
            _logger.LogInformation("Password reset requested for email: {Email}", model.Email);

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
            if (user == null)
            {
                _logger.LogWarning("Password reset request failed. User not found for email: {Email}", model.Email);
                return Ok("If the user exists, a password reset email has been sent.");
            }

            string resetToken = Guid.NewGuid().ToString();
            _logger.LogInformation("\nResetToken: " + resetToken, user.Id);

            user.PasswordResetToken = resetToken;
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);

            await _dbContext.SaveChangesAsync();
            _logger.LogInformation("Password reset token generated for user ID: {UserId}", user.Id);

            return Ok("If the user exists, a password reset email has been sent.");
        }

        [HttpPut("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            _logger.LogInformation("Password reset attempt with token: {Token}", model.Token);

            if (string.IsNullOrWhiteSpace(model.Token) || string.IsNullOrWhiteSpace(model.NewPassword))
            {
                _logger.LogWarning("Password reset failed. Missing token or new password.");
                return BadRequest("Both token and new password are required.");
            }

            // Find the user by token
            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == model.Token);
            if (user == null)
            {
                _logger.LogWarning("Password reset failed. Invalid token: {Token}", model.Token);
                return BadRequest("Invalid or expired token.");
            }

            if (user.PasswordResetTokenExpiry < DateTime.UtcNow)
            {
                _logger.LogWarning("Password reset failed. Token expired for user ID: {UserId}", user.Id);
                return BadRequest("Invalid or expired token.");
            }

            // Update the user's password
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
            user.PasswordResetToken = null; // Clear the token
            user.PasswordResetTokenExpiry = null;

            await _dbContext.SaveChangesAsync();
            _logger.LogInformation("Password successfully reset for user ID: {UserId}", user.Id);

            return Ok("Password has been successfully reset.");
        }

        // Helper method to generate JWT token
        private (string Token, DateTime Expiry) GenerateJwtToken(User user)
        {
            string? secretKey = Environment.GetEnvironmentVariable("JWT_SECRET");
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("JWT SecretKey is not configured. Set the 'JWT_SECRET' environment variable.");
            }

            SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(secretKey));
            SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);

            // Use distinct claim types
            Claim[] claims =
            [
        new Claim(JwtRegisteredClaimNames.Sub, user.Username),  // For username
        new Claim(JwtRegisteredClaimNames.Email, user.Email),   // For email
        new Claim("userid", user.Id.ToString())                 // Custom claim for user ID
    ];

            DateTime expiry = DateTime.UtcNow.AddHours(1);

            JwtSecurityToken token = new(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expiry,
                signingCredentials: creds);

            return (new JwtSecurityTokenHandler().WriteToken(token), expiry);
        }


        private string GenerateQrCodeUrl(string email, string secretKey)
        {
            return $"otpauth://totp/CigarCertifierAPI:{email}?secret={secretKey}&issuer=CigarCertifierAPI";
        }

        private string GenerateQrCodeBase64(string qrCodeUrl)
        {
            using QRCodeGenerator qrGenerator = new();
            using QRCodeData qrCodeData = qrGenerator.CreateQrCode(qrCodeUrl, QRCodeGenerator.ECCLevel.Q);
            using PngByteQRCode qrCode = new(qrCodeData);
            byte[] qrCodeImage = qrCode.GetGraphic(20);

            return Convert.ToBase64String(qrCodeImage);
        }
    }
}*/


//using System.IdentityModel.Tokens.Jwt;
//using System.Text;
//using CigarCertifierAPI.Configurations;
//using CigarCertifierAPI.Data;
//using CigarCertifierAPI.Services;
//using CigarCertifierAPI.Utilities;
//using DotNetEnv;
//using Hangfire;
//using Microsoft.AspNetCore.Authentication.JwtBearer;
//using Microsoft.AspNetCore.DataProtection;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.Extensions.Options;
//using Microsoft.IdentityModel.Tokens;

//internal class Program
//{
//    private static void Main(string[] args)
//    {
//        // Load environment variables from .env file
//        Env.Load();

//        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

//        builder.Configuration.AddEnvironmentVariables();

//        // Logging configuration
//        builder.Logging.ClearProviders();
//        builder.Logging.AddConsole();
//        builder.Logging.AddDebug();

//        IServiceCollection services = builder.Services;
//        ConfigurationManager configuration = builder.Configuration;

//        // Register JwtSettings
//        services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
//        services.AddSingleton(provider =>
//            provider.GetRequiredService<IOptions<JwtSettings>>().Value);

//        builder.Services.AddDataProtection()
//    .PersistKeysToFileSystem(new DirectoryInfo("/root/.aspnet/DataProtection-Keys"))
//    .SetApplicationName("CigarCertifierAPI");

//        // Add Hangfire services
//        services.AddHangfire(config => config
//            .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
//            .UseSimpleAssemblyNameTypeSerializer()
//            .UseRecommendedSerializerSettings()
//            .UseSqlServerStorage(configuration.GetConnectionString("DefaultConnection")));

//        services.AddHangfireServer();

//        // Add EF Core
//        services.AddDbContext<ApplicationDbContext>(options =>
//            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

//        // JWT configuration
//        JwtSettings jwtSettings = configuration.GetSection("Jwt").Get<JwtSettings>()
//                                    ?? throw new InvalidOperationException("JWT settings are not configured properly.");
//        services.AddSingleton(jwtSettings);

//        string jwtSecret = builder.Configuration["JWT_SECRET"]
//           ?? throw new InvalidOperationException("JWT_SECRET is not set.");
//        Console.WriteLine($"JWT_SECRET: {jwtSecret}");

//        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtSecret));

//        // Add Authentication
//        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//            .AddJwtBearer(options =>
//            {
//                options.TokenValidationParameters = new TokenValidationParameters
//                {
//                    ValidateIssuer = true,
//                    ValidateAudience = true,
//                    ValidateLifetime = true,
//                    ValidateIssuerSigningKey = true,
//                    ValidIssuer = jwtSettings.Issuer,
//                    ValidAudience = jwtSettings.Audience,
//                    IssuerSigningKey = key
//                };

//                // Custom token validation for blacklist
//                options.Events = new JwtBearerEvents
//                {
//                    OnTokenValidated = async context =>
//                    {
//                        ILogger logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
//                        ApplicationDbContext dbContext = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();

//                        if (context.SecurityToken is JwtSecurityToken jwtToken)
//                        {
//                            string token = jwtToken.RawData;
//                            if (!await TokenHelper.IsTokenValid(token, dbContext))
//                            {
//                                logger.LogWarning("Token is invalid or blacklisted: {Token}", token);
//                                context.Fail("This token is invalid or revoked.");
//                            }
//                            else
//                            {
//                                logger.LogInformation("Token validated: {Token}", token);
//                            }
//                        }
//                        else
//                        {
//                            logger.LogWarning("Security token is not a valid JwtSecurityToken.");
//                            context.Fail("Invalid token type.");
//                        }
//                    }
//                };
//            });

//        services.AddAuthorization();

//        // Register services
//        services.AddScoped<TokenCleanupService>();
//        services.AddScoped<LoggerService>();

//        // Add controllers
//        services.AddControllers();

//        WebApplication app = builder.Build();

//        // Use Hangfire Dashboard (Optional)
//        app.UseHangfireDashboard();

//        // Schedule cleanup job
//        RecurringJob.AddOrUpdate<TokenCleanupService>(
//            "CleanupExpiredTokens",
//            service => service.CleanupExpiredTokensAsync(),
//            Cron.Hourly);

//        app.UseHttpsRedirection();
//        //   app.UseStaticFiles();
//        app.UseRouting();
//        app.UseAuthentication();
//        app.UseAuthorization();
//        app.MapControllers();
//        app.Run();
//    }
//}