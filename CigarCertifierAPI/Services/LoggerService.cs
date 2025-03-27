using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;

namespace CigarCertifierAPI.Services
{
    public class LoggerService
    {
        private readonly ILogger<LoggerService> _logger;

        // Define message templates as constants
        private const string RegistrationAttemptMessage = "Attempting to register a new user.";
        private const string RegistrationSuccessMessage = "User registered successfully.";
        private const string RegistrationFailedMessage = "Registration failed. Username is already taken.";
        private const string LoginAttemptMessage = "Attempting to log in a user.";
        private const string LoginFailedMessage = "Login failed. Invalid credentials.";
        private const string LoginSuccessMessage = "User logged in successfully.";
        private const string GeneratedResetTokenMessage = "Generated password reset token for user ID: {UserId}";
        private const string PasswordResetRequestedMessage = "Password reset requested.";
        private const string PasswordResetRequestFailedMessage = "Password reset request failed. User not found.";
        private const string LogoutFailedInvalidTokenMessage = "Logout failed. Invalid token or blacklisted.";
        private const string TokenValidationFailedMessage = "Token validation failed for token: {Token}";
        private const string PasswordResetSuccessMessage = "Password successfully reset for user ID: {UserId}.";
        private const string Missing2FATokenMessage = "Login failed. 2FA token not provided.";
        private const string Invalid2FATokenMessage = "Login failed. Invalid 2FA token.";
        private const string LogoutFailedNoTokenMessage = "Logout failed. No token provided in Authorization header.";
        private const string LogoutFailedNoExpiryMessage = "Logout failed. Token does not have an expiry.";
        private const string LogoutSuccessMessage = "User successfully logged out.";
        private const string InvalidUserIdClaimMessage = "Invalid or missing user ID claim.";
        private const string UserNotFoundMessage = "User not found for ID: {UserId}";
        private const string TwoFAStatusRetrievedMessage = "2FA status retrieved for user ID: {UserId}";
        private const string ProtectedSuccessMessage = "Access granted to protected endpoint.";
        private const string PasswordResetAttemptMessage = "Password reset attempt.";
        private const string PasswordResetTokenGeneratedMessage = "Password reset token generated for user ID: {UserId}";
        private const string PasswordResetFailedMessage = "Password reset failed. Invalid or expired token.";
        private const string TwoFactorSetupSuccessful = "2FA setup successful for user ID: {UserId}";
        private const string TokenValidatedMessage = "Token validated.";
        private const string TokenBlacklistedMessage = "Token is blacklisted.";
        private const string UnexpectedTwoFactorError = "An unexpected error occurred during 2FA setup.";
        private const string AttemptActivate2fa = "Attempting to activate 2FA for user ID: {UserId}";
        private const string SuccessfullyActivated2fa = "2FA activated successfully for user ID: {UserId}";
        private const string Unexpected2FAError = "An unexpected error occurred during 2FA activation.";

        public LoggerService(ILogger<LoggerService> logger)
        {
            _logger = logger;
        }

        private void LogEvent(string message, params object[] args)
        {
            _logger.LogInformation(message, args);
        }

        private void LogWarning(string message, params object[] args)
        {
            try
            {
                _logger.LogWarning(message, args);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while logging a warning: {Message}", message);
            }
        }

        public void LogError(Exception ex, string message, params object[] args)
        {
            _logger.LogError(ex, message, args);
        }

        private void LogDebug(string message, params object[] args)
        {
            try
            {
                _logger.LogDebug(message, args);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while logging a debug message: {Message}", message);
            }
        }

        public void LogGeneratedResetToken(int userId)
        {
            LogDebug(GeneratedResetTokenMessage, userId);
        }

        public void LogRegistrationAttempt()
        {
            LogEvent(RegistrationAttemptMessage);
        }

        public void LogRegistrationSuccess()
        {
            LogEvent(RegistrationSuccessMessage);
        }

        public void LogRegistrationFailed()
        {
            LogWarning(RegistrationFailedMessage);
        }

        public void LogLoginAttempt()
        {
            LogEvent(LoginAttemptMessage);
        }

        public void LogLoginFailed()
        {
            LogWarning(LoginFailedMessage);
        }

        public void LogLoginSuccess()
        {
            LogEvent(LoginSuccessMessage);
        }

        public void Log2FASetupSuccess(int userId)
        {
            LogEvent(TwoFactorSetupSuccessful, userId);
        }

        public void LogPasswordResetRequested()
        {
            LogEvent(PasswordResetRequestedMessage);
        }

        public void LogPasswordResetRequestFailed()
        {
            LogWarning(PasswordResetRequestFailedMessage);
        }

        public void LogLogoutFailedInvalidToken()
        {
            LogWarning(LogoutFailedInvalidTokenMessage);
        }

        public void LogTokenValidationFailed(string token)
        {
            _logger.LogWarning(TokenValidationFailedMessage, Redact(token));
        }

        private string Redact(string input)
        {
            if (string.IsNullOrEmpty(input) || input.Length < 8)
                return "***";
            return $"{input.Substring(0, 4)}****";
        }

        public void LogPasswordResetSuccess(int userId)
        {
            LogEvent(PasswordResetSuccessMessage, userId);
        }

        public void LogMissing2FAToken()
        {
            LogWarning(Missing2FATokenMessage);
        }

        public void LogInvalid2FAToken()
        {
            LogWarning(Invalid2FATokenMessage);
        }

        public void LogLogoutFailedNoToken()
        {
            LogWarning(LogoutFailedNoTokenMessage);
        }

        public void LogLogoutFailedNoExpiry()
        {
            LogWarning(LogoutFailedNoExpiryMessage);
        }

        public void LogLogoutSuccess()
        {
            LogEvent(LogoutSuccessMessage);
        }

        public void LogInvalidUserIdClaim()
        {
            LogWarning(InvalidUserIdClaimMessage);
        }

        public void LogUserNotFound(int userId)
        {
            LogWarning(UserNotFoundMessage, userId);
        }

        public void Log2FAStatusRetrieved(int userId)
        {
            LogEvent(TwoFAStatusRetrievedMessage, userId);
        }

        public void LogProtectedSuccess()
        {
            LogEvent(ProtectedSuccessMessage);
        }

        public void LogPasswordResetAttempt()
        {
            LogEvent(PasswordResetAttemptMessage);
        }

        public void LogPasswordResetTokenGenerated(int userId)
        {
            LogEvent(PasswordResetTokenGeneratedMessage, userId);
        }

        public void LogPasswordResetFailed()
        {
            LogWarning(PasswordResetFailedMessage);
        }

        public void LogTokenValidated()
        {
            LogEvent(TokenValidatedMessage);
        }

        public void LogTokenBlacklisted()
        {
            LogWarning(TokenBlacklistedMessage);
        }

        public void LogUnexpectedTwoFactorError()
        {
            LogWarning(UnexpectedTwoFactorError);
        }

        public void Log2FAActivationAttempt(int userId)
        {
            LogEvent(AttemptActivate2fa, userId);
        }

        public void Log2FAActivationSuccess(int userId)
        {
            LogEvent(SuccessfullyActivated2fa, userId);
        }

        public void Log2FAActivationFailed(int userId)
        {
            LogWarning(Unexpected2FAError, userId);
        }

        public void LogModelStateErrors(ModelStateDictionary modelState)
        {
            foreach (var modelStateEntry in modelState)
            {
                var errors = modelStateEntry.Value.Errors;
                foreach (var error in errors)
                {
                    _logger.LogWarning("Validation error on {Key}: {ErrorMessage}",
                        modelStateEntry.Key,
                        error.ErrorMessage);
                }
            }
        }
    }
}
