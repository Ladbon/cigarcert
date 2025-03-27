using System.ComponentModel.DataAnnotations;

using CigarCertifierAPI.Configurations;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Dto;
using CigarCertifierAPI.Models;
using CigarCertifierAPI.Services;
using CigarCertifierAPI.Utilities;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

using OtpNet;

namespace CigarCertifierAPI.Controllers
{

    /// <summary>
    /// Handles user authentication, registration, 2FA setup and activation, login, logout, password resets, 
    /// and token refresh functionalities. It interacts with the database context for user data and 
    /// uses services like EmailService, LoggerService, and utility classes for JWT handling.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly LoggerService _loggerService;
        private readonly JwtSettings _jwtSettings;
        private readonly EmailService _emailService;

        public AuthController(
            ApplicationDbContext dbContext,
            LoggerService loggerService,
            JwtSettings jwtSettings,
            EmailService emailService)
        {
            _dbContext = dbContext;
            _loggerService = loggerService;
            _jwtSettings = jwtSettings;
            _emailService = emailService;
        }

        /// <summary>
        /// Registers a new user and sends a confirmation code via email.
        /// </summary>
        /// <param name="model">The registration details.</param>
        /// <returns>A message indicating the result of the registration.</returns>
        /// <response code="200">Registration successful.</response>
        /// <response code="400">Registration failed due to invalid input or username/email already taken.</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register([FromBody, Required] RegisterDto model)
        {
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

            // Check for existing username
            if (await _dbContext.Users.AnyAsync(u => u.Username == model.Username))
            {
                _loggerService.LogRegistrationFailed();
                ModelState.AddModelError("Username", "Username is already taken.");
                return BadRequest(ModelState);
            }

            // Check for existing email
            if (await _dbContext.Users.AnyAsync(u => u.Email == model.Email))
            {
                _loggerService.LogRegistrationFailed();
                ModelState.AddModelError("Email", "Email is already registered.");
                return BadRequest(ModelState);
            }

            string passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);

            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                PasswordHash = passwordHash,
                IsTwoFactorEnabled = false,
                EmailConfirmed = false,
                EmailConfirmationCode = CodeGenerator.GenerateNumericCode(6),
                EmailConfirmationCodeExpiry = DateTime.UtcNow.AddMinutes(15),
                LastEmailConfirmationSentAt = DateTime.UtcNow
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Send confirmation code via email
            string emailSubject = "Your Email Confirmation Code";
            string emailBody = $@"
                <p>Dear {user.Username},</p>
                <p>Thank you for registering. Your confirmation code is:</p>
                <h2>{user.EmailConfirmationCode}</h2>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not register, please ignore this email.</p>";

            try
            {
                await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);
            }
            catch (Exception ex)
            {
                _loggerService.LogError(ex, "Failed to send email confirmation code to {Email}", user.Email);
            }

            _loggerService.LogRegistrationSuccess();
            return Ok(new MessageResponseDto { Message = "Please check your email for the confirmation code." });
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
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

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
                //user.IsTwoFactorEnabled = true;
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
                _loggerService.LogUnexpectedTwoFactorError();
                return StatusCode(500, "An unexpected error occurred.");
            }
        }

        /// <summary>
        /// Activates two-factor authentication for the logged-in user.
        /// </summary>
        /// <param name="model">The verification code provided by the user.</param>
        /// <returns>A message indicating the result of the 2FA activation.</returns>
        /// <response code="200">2FA activation successful.</response>
        /// <response code="400">Invalid input or verification code.</response>
        /// <response code="404">User not found.</response>
        /// <response code="500">An unexpected error occurred.</response>
        [Authorize]
        [HttpPost("activate-2fa")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ActivateTwoFactor([FromBody] ActivateTwoFactorDto model)
        {
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

            int id = 0;

            try
            {
                int? userIdNullable = JwtHelper.GetUserIdFromClaims(User);
                if (userIdNullable == null)
                {
                    _loggerService.LogInvalidUserIdClaim();
                    return BadRequest(new MessageResponseDto { Message = "Invalid or missing 'userid' claim." });
                }

                int userId = userIdNullable.Value;
                id = userId;
                User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user == null)
                {
                    _loggerService.LogUserNotFound(userId);
                    return NotFound(new MessageResponseDto { Message = "User not found." });
                }

                if (string.IsNullOrEmpty(user.TwoFactorSecret))
                {
                    _loggerService.Log2FAActivationFailed(userId);
                    return BadRequest(new MessageResponseDto { Message = "2FA has not been set up for this user." });
                }

                _loggerService.Log2FAActivationAttempt(userId);

                var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
                bool isValid = totp.VerifyTotp(model.VerificationCode, out _);

                if (!isValid)
                {
                    _loggerService.LogInvalid2FAToken();
                    return BadRequest(new MessageResponseDto { Message = "Invalid verification code." });
                }

                user.IsTwoFactorEnabled = true;
                await _dbContext.SaveChangesAsync();

                _loggerService.Log2FAActivationSuccess(userId);

                return Ok(new MessageResponseDto { Message = "Two-Factor Authentication activated successfully." });
            }
            catch (Exception ex)
            {
                _loggerService.LogError(ex, "An error occurred while activating 2FA for user ID: {UserId}", id);
                return StatusCode(500, new MessageResponseDto { Message = "An unexpected error occurred." });
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
        /// <returns>A JWT token if login is successful, or indicates that 2FA is required.</returns>
        /// <response code="200">Login successful or 2FA is required.</response>
        /// <response code="401">Invalid username, password, or 2FA token.</response>
        [HttpPost("login")]
        [EnableRateLimiting("LoginPolicy")]
        [ProducesResponseType(typeof(LoginResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody, Required] LoginDto model)
        {
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

            _loggerService.LogLoginAttempt();

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !PasswordHelper.VerifyPassword(model.Password, user.PasswordHash))
            {
                _loggerService.LogLoginAttempt();
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "Invalid credentials." });
            }

            if (!user.EmailConfirmed)
            {
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "Email not confirmed. Please check your email to confirm your account." });
            }

            if (user.IsTwoFactorEnabled)
            {
                if (string.IsNullOrWhiteSpace(model.TwoFactorToken))
                {
                    _loggerService.LogMissing2FAToken();
                    return Ok(new LoginResponseDto
                    {
                        IsTwoFactorRequired = true,
                        Message = "Two-factor authentication is required."
                    });
                }

                // Validate the 2FA token
                var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
                if (!totp.VerifyTotp(model.TwoFactorToken, out _))
                {
                    _loggerService.LogInvalid2FAToken();
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
                SetAuthCookie(existingToken.Token, existingToken.ExpiresAt);

                return Ok(new LoginResponseDto
                {
                    IsTwoFactorRequired = false,
                    Token = null, // Token is stored in HttpOnly cookie
                    ExpiresAt = existingToken.ExpiresAt,
                    Message = "User is already logged in."
                });
            }

            if (existingToken != null && isTokenBlacklisted)
            {
                _loggerService.LogTokenValidationFailed(existingToken.Token);
            }

            // Generate new JWT token
            (string token, DateTime expiry) = JwtHelper.GenerateJwtToken(user, _jwtSettings);

            // Store the new token in the ActiveTokens table
            _dbContext.ActiveTokens.Add(new ActiveToken
            {
                Token = token,
                UserId = user.Id,
                ExpiresAt = expiry
            });
            await _dbContext.SaveChangesAsync();

            // Set HttpOnly cookie
            SetAuthCookie(token, expiry);

            _loggerService.LogLoginSuccess();
            return Ok(new LoginResponseDto
            {
                IsTwoFactorRequired = false,
                Token = null, // Token is stored in HttpOnly cookie
                ExpiresAt = expiry,
                Message = "Login successful."
            });
        }

        /// <summary>
        /// Helper method to set the authentication token in an HttpOnly cookie.
        /// </summary>
        /// <param name="token">The JWT token to set.</param>
        /// <param name="expiresAt">The expiry date of the token.</param>
        private void SetAuthCookie(string token, DateTime expiresAt)
        {
            Response.Cookies.Append("token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/",    // Add explicit path to ensure cookie is sent to all endpoints
                Expires = expiresAt
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
            string? token = Request.Cookies["token"];

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
            }

            await _dbContext.SaveChangesAsync();

            // Delete the token cookie
            Response.Cookies.Delete("token");

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
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

            _loggerService.LogPasswordResetRequested();

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
            if (user == null)
            {
                _loggerService.LogPasswordResetRequestFailed();
                return Ok("If the user exists, a password reset email has been sent.");
            }

            var activeTokens = await _dbContext.ActiveTokens
                .Where(t => t.UserId == user.Id)
                .ToListAsync();

            // Add all active tokens to blacklist and remove them
            foreach (var token in activeTokens)
            {
                _dbContext.BlacklistedTokens.Add(new BlacklistedToken
                {
                    Token = token.Token,
                    ExpiresAt = token.ExpiresAt
                });
                _dbContext.ActiveTokens.Remove(token);
            }

            string resetToken = GuidHelper.GenerateGuid();
            _loggerService.LogGeneratedResetToken(user.Id);

            user.PasswordResetToken = resetToken;
            user.PasswordResetTokenExpiry = DateTimeHelper.GetUtcNow().AddHours(1);

            await _dbContext.SaveChangesAsync();
            _loggerService.LogPasswordResetTokenGenerated(user.Id);

            // Send password reset email
            string frontendBaseUrl = "https://localhost:4200"; // Frontend URL
            string resetLink = $"{frontendBaseUrl}/reset-password?token={resetToken}";
            string emailSubject = "Password Reset Request";
            string emailBody = $@"
                                <p>Dear {user.Username},</p>
                                <p>You requested a password reset. Click the link below to reset your password:</p>
                                <p><a href='{resetLink}'>Reset Password</a></p>
                                <p>If you did not request this, please ignore this email.</p>";

            try
            {
                await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);
            }
            catch (Exception ex)
            {
                _loggerService.LogError(ex, "Failed to send email confirmation code to [REDACTED EMAIL]");
                _loggerService.LogGeneratedResetToken(user.Id);
            }

            return Ok(new MessageResponseDto { Message = "If the user exists, a password reset email has been sent." });
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
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(ModelState);
            }

            _loggerService.LogPasswordResetAttempt();

            if (string.IsNullOrWhiteSpace(model.Token) || string.IsNullOrWhiteSpace(model.NewPassword))
            {
                _loggerService.LogPasswordResetFailed();
                return BadRequest("Both token and new password are required.");
            }

            User? user = await _dbContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == model.Token);

            if (user == null || DateTimeHelper.IsExpired(user.PasswordResetTokenExpiry))
            {
                _loggerService.LogPasswordResetFailed();
                return BadRequest("Invalid or expired token.");
            }

            user.PasswordHash = PasswordHelper.HashPassword(model.NewPassword);
            user.PasswordResetToken = null;
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

        /// <summary>
        /// Refreshes the JWT token for the logged-in user.
        /// </summary>
        /// <returns>A new JWT token with the updated expiry time.</returns>
        /// <response code="200">Token refreshed successfully.</response>
        /// <response code="400">Token is required or invalid input.</response>
        /// <response code="401">Invalid or expired token, or user not found.</response>
        [Authorize]
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(LoginResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponseDto), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> RefreshToken()
        {
            // Extract the user ID from claims
            int? userId = JwtHelper.GetUserIdFromClaims(User);
            if (userId == null)
            {
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "Invalid token." });
            }

            // Retrieve the user
            var user = await _dbContext.Users.FindAsync(userId.Value);
            if (user == null)
            {
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "User not found." });
            }

            // Retrieve the current token from the cookie
            string? oldToken = Request.Cookies["token"];
            if (string.IsNullOrEmpty(oldToken))
            {
                return BadRequest(new ErrorResponseDto { ErrorMessage = "Token is required." });
            }

            // Validate the current token
            bool isValid = await TokenHelper.IsTokenValid(oldToken, _dbContext);
            if (!isValid)
            {
                return Unauthorized(new ErrorResponseDto { ErrorMessage = "Invalid or expired token." });
            }

            // Remove the old active token
            var activeToken = await _dbContext.ActiveTokens.FirstOrDefaultAsync(at => at.Token == oldToken);
            if (activeToken != null)
            {
                _dbContext.ActiveTokens.Remove(activeToken);
            }

            // Generate a new token
            var (newToken, expiry) = JwtHelper.GenerateJwtToken(user, _jwtSettings);

            // Add the new token to active tokens
            _dbContext.ActiveTokens.Add(new ActiveToken
            {
                Token = newToken,
                UserId = user.Id,
                ExpiresAt = expiry
            });

            await _dbContext.SaveChangesAsync();

            // Set the new token in the HttpOnly cookie
            SetAuthCookie(newToken, expiry);

            return Ok(new LoginResponseDto
            {
                IsTwoFactorRequired = false,
                Token = null, // Token is stored in HttpOnly cookie
                ExpiresAt = expiry,
                Message = "Token refreshed successfully."
            });
        }

        /// <summary>
        /// Confirms a user's email using the confirmation code.
        /// </summary>
        /// <param name="model">The email confirmation details.</param>
        /// <returns>A message indicating the result of the email confirmation.</returns>
        /// <response code="200">Email confirmed successfully.</response>
        /// <response code="400">Invalid code or code expired.</response>
        [HttpPost("confirm-email")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ConfirmEmail([FromBody, Required] EmailConfirmationDto model)
        {
            if (!ModelState.IsValid)
            {
                _loggerService.LogModelStateErrors(ModelState);
                return BadRequest(new MessageResponseDto { Message = "Email and confirmation code are required." });
            }

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == model.Email);

            if (user == null)
            {
                return BadRequest(new MessageResponseDto { Message = "Invalid email or confirmation code." });
            }

            if (user.EmailConfirmed)
            {
                return Ok(new MessageResponseDto { Message = "Email is already confirmed." });
            }

            if (user.EmailConfirmationCodeExpiry < DateTime.UtcNow)
            {
                return BadRequest(new MessageResponseDto { Message = "Confirmation code has expired." });
            }

            if (user.EmailConfirmationCode != model.ConfirmationCode)
            {
                return BadRequest(new MessageResponseDto { Message = "Invalid confirmation code." });
            }

            user.EmailConfirmed = true;
            user.EmailConfirmationCode = null;
            user.EmailConfirmationCodeExpiry = null;

            await _dbContext.SaveChangesAsync();

            return Ok(new MessageResponseDto { Message = "Email confirmed successfully. You can now log in." });
        }

        /// <summary>
        /// Resends the email confirmation code to the user.
        /// </summary>
        /// <param name="email">The email address of the user.</param>
        /// <returns>A message indicating the result of the resend operation.</returns>
        /// <response code="200">Confirmation code resent successfully.</response>
        /// <response code="400">Resend attempt too soon or user not found.</response>
        [HttpPost("resend-confirmation-code")]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status429TooManyRequests)]
        public async Task<IActionResult> ResendConfirmationCode([FromBody][Required][EmailAddress] string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return BadRequest(new MessageResponseDto { Message = "Email is required." });
            }

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                return BadRequest(new MessageResponseDto { Message = "User not found." });
            }

            if (user.EmailConfirmed)
            {
                return Ok(new MessageResponseDto { Message = "Email is already confirmed." });
            }

            // Rate limiting configuration
            const int maxAttempts = 3; // Maximum resend attempts
            const int attemptWindowMinutes = 15; // Time window in minutes

            // Calculate time since last attempt
            if (user.LastEmailConfirmationSentAt.HasValue)
            {
                var timeSinceLastAttempt = DateTime.UtcNow - user.LastEmailConfirmationSentAt.Value;

                if (timeSinceLastAttempt.TotalMinutes < attemptWindowMinutes)
                {
                    if (user.EmailConfirmationAttempts >= maxAttempts)
                    {
                        var retryAfter = attemptWindowMinutes - timeSinceLastAttempt.TotalMinutes;

                        // Add Retry-After header
                        Response.Headers.RetryAfter = ((int)(retryAfter * 60)).ToString();

                        return StatusCode(StatusCodes.Status429TooManyRequests, new MessageResponseDto
                        {
                            Message = $"Maximum resend attempts reached. Please try again after {retryAfter:F0} minutes."
                        });
                    }

                    user.EmailConfirmationAttempts += 1;
                }
                else
                {
                    // Reset attempts after the time window has passed
                    user.EmailConfirmationAttempts = 1;
                }
            }
            else
            {
                user.EmailConfirmationAttempts = 1;
            }

            user.LastEmailConfirmationSentAt = DateTime.UtcNow;
            user.EmailConfirmationCode = CodeGenerator.GenerateNumericCode(6);
            user.EmailConfirmationCodeExpiry = DateTime.UtcNow.AddMinutes(15);

            await _dbContext.SaveChangesAsync();

            // Send confirmation code via email
            string emailSubject = "Your Email Confirmation Code";
            string emailBody = $@"
        <p>Dear {user.Username},</p>
        <p>Your new confirmation code is:</p>
        <h2>{user.EmailConfirmationCode}</h2>
        <p>This code will expire in 15 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>";

            try
            {
                await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);
            }
            catch (Exception ex)
            {
                _loggerService.LogError(ex, "Failed to resend email confirmation code to {Email}", user.Email);
            }

            return Ok(new MessageResponseDto { Message = "Confirmation code resent successfully! Please check your email, including your junk mail folder." });
        }
    }
}