using System.ComponentModel.DataAnnotations;

using CigarCertifierAPI.Configurations;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Dto;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using CigarCertifierAPI.Utilities;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using OtpNet;

namespace CigarCertifierAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly LoggerService _loggerService;
        private readonly JwtSettings _jwtSettings;

        public AuthController(
            ApplicationDbContext dbContext,
            LoggerService loggerService,
            JwtSettings jwtSettings)
        {
            _dbContext = dbContext;
            _loggerService = loggerService;
            _jwtSettings = jwtSettings;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody, Required] RegisterDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            _loggerService.LogRegistrationAttempt(model.Username);

            if (await _dbContext.Users.AnyAsync(u => u.Username == model.Username))
            {
                _loggerService.LogRegistrationFailed(model.Username);
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

            _loggerService.LogRegistrationSuccess(model.Username);
            return Ok("User registered successfully!");
        }

        [Authorize]
        [HttpPatch("setup-2fa")]
        public async Task<IActionResult> SetupTwoFactor()
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                int userId = JwtHelper.GetUserIdFromClaims(User);

                User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user == null)
                {
                    _loggerService.LogUserNotFound(userId);
                    return NotFound("User not found.");
                }

                byte[] newSecretKey = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecret = Base32Encoding.ToString(newSecretKey);
                user.IsTwoFactorEnabled = true;
                await _dbContext.SaveChangesAsync();

                string qrCodeUrl = QrCodeHelper.GenerateQrCodeUrl(user.Email, user.TwoFactorSecret);
                string qrCodeBase64 = QrCodeHelper.GenerateQrCodeBase64(qrCodeUrl);

                _loggerService.Log2FASetupSuccess(user.Id);

                return Ok(new
                {
                    message = "2FA setup successful.",
                    qrCode = $"data:image/png;base64,{qrCodeBase64}",
                    secretKey = user.TwoFactorSecret
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                _loggerService.LogInvalidUserIdClaim();
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _loggerService.LogUnexpectedTwoFactorError(ex.Message);
                return StatusCode(500, "An unexpected error occurred.");
            }
        }


        [Authorize]
        [HttpGet("2fa-status")]
        public async Task<IActionResult> GetTwoFactorStatus()
        {
            try
            {
                int userId = JwtHelper.GetUserIdFromClaims(User);


                User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user == null)
                {
                    _loggerService.LogUserNotFound(userId);
                    return NotFound("User not found.");
                }

                _loggerService.Log2FAStatusRetrieved(userId);
                return Ok(new { isTwoFactorEnabled = user.IsTwoFactorEnabled });
            }
            catch (UnauthorizedAccessException ex)
            {
                _loggerService.LogInvalidUserIdClaim();
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody, Required] LoginDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            _loggerService.LogLoginAttempt(model.Username);

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !PasswordHelper.VerifyPassword(model.Password, user.PasswordHash))
            {
                _loggerService.LogLoginFailed(model.Username);
                return Unauthorized("Invalid username or password.");
            }

            if (user.IsTwoFactorEnabled && string.IsNullOrWhiteSpace(model.TwoFactorToken))
            {
                _loggerService.LogMissing2FAToken(model.Username);
                return BadRequest("Two-factor authentication is required.");
            }

            if (user.IsTwoFactorEnabled)
            {
                Totp totp = new(Base32Encoding.ToBytes(user.TwoFactorSecret));
                if (!totp.VerifyTotp(model.TwoFactorToken, out _))
                {
                    _loggerService.LogInvalid2FAToken(model.Username);
                    return Unauthorized("Invalid 2FA token.");
                }
            }

            // Check if a valid token already exists for the user
            var existingToken = await _dbContext.ActiveTokens
                .Where(t => t.UserId == user.Id && t.ExpiresAt > DateTime.UtcNow)
                .FirstOrDefaultAsync();

            // Check if the existing token is blacklisted
            bool isTokenBlacklisted = existingToken != null && await TokenHelper.IsTokenBlacklisted(existingToken.Token, _dbContext);

            if (existingToken != null && !isTokenBlacklisted)
            {
                // User is already logged in
                return Ok(new { Message = "User is already logged in.", existingToken.Token, existingToken.ExpiresAt });
            }

            (string token, DateTime expiry) = JwtHelper.GenerateJwtToken(user, _jwtSettings);

            // Store the new token in the ActiveTokens table using ActiveTokenDto
            ActiveTokenDto newActiveToken = new()
            {
                Token = token,
                UserId = user.Id,
                ExpiresAt = expiry
            };

            _dbContext.ActiveTokens.Add(new ActiveToken
            {
                Token = newActiveToken.Token,
                UserId = newActiveToken.UserId,
                ExpiresAt = newActiveToken.ExpiresAt
            });
            await _dbContext.SaveChangesAsync();

            _loggerService.LogLoginSuccess(model.Username);
            return Ok(new { Token = token, ExpiresAt = expiry });
        }

        [Authorize]
        [HttpDelete("logout")]
        public async Task<IActionResult> Logout()
        {
            string? token = HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Split(" ").Last();

            if (string.IsNullOrEmpty(token))
            {
                _loggerService.LogLogoutFailedNoToken();
                return BadRequest("No token provided.");
            }

            if (!TokenHelper.IsValidToken(token))
            {
                _loggerService.LogLogoutFailedInvalidToken();
                return BadRequest("Invalid token format.");
            }

            if (await TokenHelper.IsTokenBlacklisted(token, _dbContext))
            {
                _loggerService.LogLogoutFailedInvalidToken();
                return BadRequest("Token has already been revoked.");
            }

            DateTime? expiry = TokenHelper.GetTokenExpiry(token);
            if (expiry == null || expiry <= DateTime.UtcNow)
            {
                _loggerService.LogLogoutFailedNoExpiry();
                return BadRequest("Token has already expired.");
            }

            // Add token to blacklist
            BlacklistedToken blacklistedToken = new()
            {
                Token = token,
                ExpiresAt = expiry.Value
            };
            _dbContext.BlacklistedTokens.Add(blacklistedToken);

            // Remove the active token
            var activeToken = await _dbContext.ActiveTokens.FirstOrDefaultAsync(at => at.Token == token);
            if (activeToken != null)
            {
                _dbContext.ActiveTokens.Remove(activeToken);
                await _dbContext.SaveChangesAsync();
            }

            await _dbContext.SaveChangesAsync();

            _loggerService.LogLogoutSuccess();
            return Ok("You have been logged out.");
        }

        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto model)
        {
            _loggerService.LogPasswordResetRequested(model.Email);

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
            if (user == null)
            {
                _loggerService.LogPasswordResetRequestFailed(model.Email);
                return Ok("If the user exists, a password reset email has been sent.");
            }

            string resetToken = GuidHelper.GenerateGuid();
            _loggerService.LogGeneratedResetToken(resetToken, user.Id);

            user.PasswordResetToken = resetToken;
            user.PasswordResetTokenExpiry = DateTimeHelper.GetUtcNow().AddHours(1);

            await _dbContext.SaveChangesAsync();
            _loggerService.LogPasswordResetTokenGenerated(user.Id);

            return Ok("If the user exists, a password reset email has been sent.");
        }

        [HttpPut("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            _loggerService.LogPasswordResetAttempt(model.Token);

            if (string.IsNullOrWhiteSpace(model.Token) || string.IsNullOrWhiteSpace(model.NewPassword))
            {
                _loggerService.LogPasswordResetFailed(model.Token);
                return BadRequest("Both token and new password are required.");
            }

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == model.Token);

            if (user == null || DateTimeHelper.IsExpired(user.PasswordResetTokenExpiry))
            {
                _loggerService.LogPasswordResetFailed(model.Token);
                return BadRequest("Invalid or expired token.");
            }

            user.PasswordHash = PasswordHelper.HashPassword(model.NewPassword);
            user.PasswordResetToken = null; // Clear the token
            user.PasswordResetTokenExpiry = null;

            await _dbContext.SaveChangesAsync();
            _loggerService.LogPasswordResetSuccess(user.Id);

            return Ok("Password has been successfully reset.");
        }


        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            _loggerService.LogProtectedSuccess();
            return Ok("You have accessed a protected endpoint!");
        }

    }
}