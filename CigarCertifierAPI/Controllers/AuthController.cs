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
    /// <summary>
    /// Handles authentication-related operations.
    /// </summary>
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

        /// <summary>
        /// Registers a new user.
        /// </summary>
        /// <param name="model">The registration details.</param>
        /// <returns>A message indicating the result of the registration.</returns>
        /// <response code="200">Registration successful.</response>
        /// <response code="400">Registration failed due to invalid input or username already taken.</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status400BadRequest)]
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
            return Ok(new MessageResponseDto { Message = "User registered successfully!" });
        }

        /// <summary>
        /// Sets up two-factor authentication for the logged-in user.
        /// </summary>
        /// <returns>A message indicating the result of the 2FA setup.</returns>
        /// <response code="200">2FA setup successful.</response>
        /// <response code="400">Invalid input or missing 'userid' claim.</response>
        /// <response code="404">User not found.</response>
        /// <response code="500">An unexpected error occurred.</response>
        [Authorize]
        [HttpPatch("setup-2fa")]
        [ProducesResponseType(typeof(TwoFactorSetupResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> SetupTwoFactor()
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                int? userId = JwtHelper.GetUserIdFromClaims(User);
                if (userId == null)
                {
                    return BadRequest(new MessageResponseDto { Message = "Invalid or missing 'userid' claim." });
                }

                User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId.Value);
                if (user == null)
                {
                    return NotFound(new MessageResponseDto { Message = "User not found." });
                }

                byte[] newSecretKey = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecret = Base32Encoding.ToString(newSecretKey);
                user.IsTwoFactorEnabled = true;
                await _dbContext.SaveChangesAsync();

                string qrCodeUrl = QrCodeHelper.GenerateQrCodeUrl(user.Email, user.TwoFactorSecret);
                string qrCodeBase64 = QrCodeHelper.GenerateQrCodeBase64(qrCodeUrl);

                _loggerService.Log2FASetupSuccess(user.Id);

                return Ok(new TwoFactorSetupResponseDto
                {
                    Message = "2FA setup successful.",
                    QrCode = $"data:image/png;base64,{qrCodeBase64}",
                    SecretKey = user.TwoFactorSecret
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

        /// <summary>
        /// Retrieves the two-factor authentication status for the logged-in user.
        /// </summary>
        /// <returns>The 2FA status of the user.</returns>
        /// <response code="200">2FA status retrieved successfully.</response>
        /// <response code="400">Invalid or missing 'userid' claim.</response>
        /// <response code="404">User not found.</response>
        [Authorize]
        [HttpGet("2fa-status")]
        [ProducesResponseType(typeof(TwoFactorStatusResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetTwoFactorStatus()
        {
            try
            {
                int? userId = JwtHelper.GetUserIdFromClaims(User);
                if (userId == null)
                {
                    return BadRequest(new MessageResponseDto { Message = "Invalid or missing 'userid' claim." });
                }

                User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId.Value);
                if (user == null)
                {
                    _loggerService.LogUserNotFound((int)userId);
                    return NotFound(new MessageResponseDto { Message = "User not found." });
                }

                _loggerService.Log2FAStatusRetrieved((int)userId);
                return Ok(new TwoFactorStatusResponseDto
                {
                    IsTwoFactorEnabled = user.IsTwoFactorEnabled
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                _loggerService.LogInvalidUserIdClaim();
                return BadRequest(new ErrorResponseDto { ErrorMessage = ex.Message });
            }
        }

        /// <summary>
        /// Logs in a user.
        /// </summary>
        /// <param name="model">The login details.</param>
        /// <returns>A JWT token if login is successful.</returns>
        /// <response code="200">Login successful.</response>
        /// <response code="400">Invalid input or 2FA token required.</response>
        /// <response code="401">Invalid username, password, or 2FA token.</response>
        [HttpPost("login")]
        [ProducesResponseType(typeof(TokenResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody, Required] LoginDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            _loggerService.LogLoginAttempt(model.Username);

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !PasswordHelper.VerifyPassword(model.Password, user.PasswordHash))
            {
                _loggerService.LogLoginFailed(model.Username);
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "Invalid username or password." });
            }

            if (user.IsTwoFactorEnabled && string.IsNullOrWhiteSpace(model.TwoFactorToken))
            {
                _loggerService.LogMissing2FAToken(model.Username);
                return BadRequest(new ErrorResponseDto { ErrorMessage = "Two-factor authentication is required." });
            }

            if (user.IsTwoFactorEnabled)
            {
                Totp totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
                if (!totp.VerifyTotp(model.TwoFactorToken, out _))
                {
                    _loggerService.LogInvalid2FAToken(model.Username);
                    return Unauthorized(new ErrorResponseDto { ErrorMessage = "Invalid 2FA token." });
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
                return Ok(new TokenResponseDto
                {
                    Message = "User is already logged in.",
                    Token = existingToken.Token,
                    ExpiresAt = existingToken.ExpiresAt
                });
            }

            (string token, DateTime expiry) = JwtHelper.GenerateJwtToken(user, _jwtSettings);

            // Store the new token in the ActiveTokens table
            _dbContext.ActiveTokens.Add(new ActiveToken
            {
                Token = token,
                UserId = user.Id,
                ExpiresAt = expiry
            });
            await _dbContext.SaveChangesAsync();

            _loggerService.LogLoginSuccess(model.Username);
            return Ok(new TokenResponseDto
            {
                Token = token,
                ExpiresAt = expiry
            });
        }

        /// <summary>
        /// Logs out the logged-in user.
        /// </summary>
        /// <returns>A message indicating the result of the logout.</returns>
        /// <response code="200">Logout successful.</response>
        /// <response code="400">No token provided, invalid token format, or token already revoked.</response>
        [Authorize]
        [HttpDelete("logout")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
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
            return Ok(new MessageResponseDto { Message = "You have been logged out." });
        }

        /// <summary>
        /// Requests a password reset for the user.
        /// </summary>
        /// <param name="model">The password reset request details.</param>
        /// <returns>A message indicating the result of the password reset request.</returns>
        /// <response code="200">Password reset request successful.</response>
        [HttpPost("request-password-reset")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
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

        /// <summary>
        /// Resets the password for the user.
        /// </summary>
        /// <param name="model">The password reset details.</param>
        /// <returns>A message indicating the result of the password reset.</returns>
        /// <response code="200">Password reset successful.</response>
        /// <response code="400">Invalid or expired token, or missing new password.</response>
        [HttpPut("reset-password")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
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

            return Ok(new MessageResponseDto { Message = "Password has been successfully reset." });
        }

        /// <summary>
        /// Accesses a protected endpoint.
        /// </summary>
        /// <returns>A message indicating access to the protected endpoint.</returns>
        /// <response code="200">Access to protected endpoint successful.</response>
        [Authorize]
        [HttpGet("protected")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        public IActionResult ProtectedEndpoint()
        {
            _loggerService.LogProtectedSuccess();
            return Ok("You have accessed a protected endpoint!");
        }
    }
}