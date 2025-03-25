using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Web.Security;
using System.Text;
namespace CigarCertifierAPI.Services
{
    public class LoggerService
    {
        private readonly ILogger<LoggerService> _logger;

        // Define message templates as constants
        private const string RegistrationAttemptMessage = "Attempting to register a new user: {Username}";
        private const string RegistrationSuccessMessage = "User {Username} registered successfully";
        private const string RegistrationFailedMessage = "Registration failed. Username {Username} is already taken.";
        private const string LoginAttemptMessage = "Attempting to log in user: {Username}";
        private const string LoginFailedMessage = "Login failed for user {Username}. Invalid credentials.";
        private const string LoginSuccessMessage = "User {Username} logged in successfully.";
        private const string GeneratedResetTokenMessage = "Generated reset token: {Token} for user ID: {UserId}";
        private const string PasswordResetRequestedMessage = "Password reset requested for email: {Email}";
        private const string PasswordResetRequestFailedMessage = "Password reset request failed. User not found for email: {Email}";
        private const string LogoutFailedInvalidTokenMessage = "Logout failed. Invalid token or blacklisted.";
        private const string TokenValidationFailedMessage = "Token validation failed for token: {Token}";
        private const string PasswordResetSuccessMessage = "Password successfully reset for user ID: {UserId}.";
        private const string Missing2FATokenMessage = "Login failed. 2FA token not provided for user: {Username}";
        private const string Invalid2FATokenMessage = "Login failed. Invalid 2FA token for user: {Username}";
        private const string LogoutFailedNoTokenMessage = "Logout failed. No token provided in Authorization header.";
        private const string LogoutFailedNoExpiryMessage = "Logout failed. Token does not have an expiry.";
        private const string LogoutSuccessMessage = "User successfully logged out.";
        private const string InvalidUserIdClaimMessage = "Invalid or missing user ID claim.";
        private const string UserNotFoundMessage = "User not found for ID: {UserId}";
        private const string TwoFAStatusRetrievedMessage = "2FA status retrieved for user ID: {UserId}";
        private const string ProtectedSuccessMessage = "Access granted to protected endpoint.";
        private const string PasswordResetAttemptMessage = "Password reset attempt with token: {Token}";
        private const string PasswordResetTokenGeneratedMessage = "Password reset token generated for user ID: {UserId}";
        private const string PasswordResetFailedMessage = "Password reset failed. Invalid or expired token: {Token}";
        private const string TwoFactorSetupSuccessful = "2FA setup successful for user ID: {UserId}";
        private const string TokenValidatedMessage = "Token validated: {Token}";
        private const string TokenBlacklistedMessage = "Token is blacklisted: {Token}";
        private const string UnexpectedTwoFactorError = "An unexpected error occurred during 2FA setup";
        private const string AttemptActivate2fa = "Attempting to activate 2FA for user ID";
        private const string SuccessfullyActivated2fa = "2FA activated successfully for user ID";
        private const string Unexpected2FAError = "An unexpected error occurred during 2FA activation";

        public LoggerService(ILogger<LoggerService> logger)
        {
            _logger = logger;
        }

        private string ProtectSensitiveInformation(string value, string type)
        {
            return Convert.ToBase64String(MachineKey.Protect(Encoding.UTF8.GetBytes(value), type));
        }

        private void LogEvent(string message, params object[] args)
        {
            var protectedArgs = args.Select(arg => arg is string ? ProtectSensitiveInformation(arg.ToString(), "LogEvent") : arg).ToArray();
            _logger.LogInformation(message, protectedArgs);
        }

        private void LogWarning(string message, params object[] args)
        {
            try
            {
                var protectedMessage = ProtectSensitiveInformation(message, "LogWarning");
                var protectedArgs = args.Select(arg => arg is string ? ProtectSensitiveInformation(arg.ToString(), "LogWarning") : arg).ToArray();
                _logger.LogWarning(protectedMessage, protectedArgs);
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
                var protectedArgs = args.Select(arg => arg is string ? ProtectSensitiveInformation(arg.ToString(), "LogDebug") : arg).ToArray();
                _logger.LogDebug(message, protectedArgs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while logging a debug message: {Message}", message);
            }
        }

        public void LogGeneratedResetToken(string token, int id)
        {
            LogDebug(GeneratedResetTokenMessage, token, id);
        }

        public void LogRegistrationAttempt(string username)
        {
            LogEvent(RegistrationAttemptMessage, username);
        }

        public void LogRegistrationSuccess(string username)
        {
            LogEvent(RegistrationSuccessMessage, username);
        }

        public void LogRegistrationFailed(string username)
        {
            LogWarning(RegistrationFailedMessage, username);
        }

        public void LogLoginAttempt(string username)
        {
            LogEvent(LoginAttemptMessage, username);
        }

        public void LogLoginFailed(string username)
        {
            LogWarning(LoginFailedMessage, username);
        }

        public void LogLoginSuccess(string username)
        {
            LogEvent(LoginSuccessMessage, username);
        }

        public void Log2FASetupSuccess(int userId)
        {
            LogEvent(TwoFactorSetupSuccessful, userId);
        }

        public void LogPasswordResetRequested(string email)
        {
            LogEvent(PasswordResetRequestedMessage, email);
        }

        public void LogPasswordResetRequestFailed(string email)
        {
            LogWarning(PasswordResetRequestFailedMessage, email);
        }

        public void LogLogoutFailedInvalidToken()
        {
            LogWarning(LogoutFailedInvalidTokenMessage);
        }

        public void LogTokenValidationFailed(string token)
        {
            _logger.LogWarning("Token validation failed for token: {RedactedToken}", Redact(token));
        }

        private string Redact(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Length < 10)
                return "***";
            return $"{token[..4]}****{token.Substring(token.Length - 4, 4)}";
        }

        public void LogPasswordResetSuccess(int userId)
        {
            LogEvent(PasswordResetSuccessMessage, userId);
        }

        public void LogMissing2FAToken(string username)
        {
            LogWarning(Missing2FATokenMessage, username);
        }

        public void LogInvalid2FAToken(string username)
        {
            LogWarning(Invalid2FATokenMessage, username);
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

        public void LogPasswordResetAttempt(string token)
        {
            LogEvent(PasswordResetAttemptMessage, token);
        }

        public void LogPasswordResetTokenGenerated(int userId)
        {
            LogEvent(PasswordResetTokenGeneratedMessage, userId);
        }

        public void LogPasswordResetFailed(string token)
        {
            LogWarning(PasswordResetFailedMessage, token);
        }

        public void LogTokenValidated(string token)
        {
            LogEvent(TokenValidatedMessage, token);
        }

        public void LogTokenBlacklisted(string token)
        {
            LogWarning(TokenBlacklistedMessage, token);
        }

        public void LogUnexpectedTwoFactorError(string message)
        {
            LogWarning($"{message} {UnexpectedTwoFactorError}");
        }

        public void Log2FAActivationAttempt(int userId)
        {
            LogEvent($"{AttemptActivate2fa} {userId}", userId);
        }

        public void Log2FAActivationSuccess(int userId)
        {
            LogEvent($"{SuccessfullyActivated2fa} {userId}", userId);
        }

        public void Log2FAActivationFailed(int userId, string reason)
        {
            LogWarning($"{Unexpected2FAError} {userId}\nReason: {reason}", userId, reason);
        }
        public void LogModelStateErrors(ModelStateDictionary modelState)
        {
            foreach (var modelStateEntry in modelState)
            {
                var errors = modelStateEntry.Value.Errors;
                foreach (var error in errors)
                {
                    _logger.LogWarning("Validation error on {Key}: {ErrorMessage}", modelStateEntry.Key, error.ErrorMessage);
                }
            }
        }
    }
}
