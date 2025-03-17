using SendGrid;
using SendGrid.Helpers.Mail;

namespace CigarCertifierAPI.Services
{
    public class EmailService
    {
        private readonly string _sendGridApiKey;
        private readonly string _senderEmail;
        private readonly string _senderName;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration)
        {
            // Retrieve SendGrid API key from environment variable or configuration
            _sendGridApiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY")
                              ?? configuration["SENDGRID_API_KEY"]
                              ?? throw new ArgumentNullException(nameof(configuration), "SendGrid API Key is missing.");

            // Retrieve sender email and name from configuration
            _senderEmail = configuration["EmailSettings:SenderEmail"] ?? "ladbon.f@gmail.com";
            _senderName = configuration["EmailSettings:SenderName"] ?? "Ladbon Fragari";

            // Initialize logger
            _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<EmailService>();
        }

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _logger = logger;

            // Retrieve SendGrid API key from environment variable or configuration
            _sendGridApiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY")
                              ?? configuration["SENDGRID_API_KEY"]
                              ?? throw new ArgumentNullException(nameof(configuration), "SendGrid API Key is missing.");

            // Retrieve sender email and name from configuration
            _senderEmail = configuration["EmailSettings:SenderEmail"] ?? "no-reply@yourdomain.com";
            _senderName = configuration["EmailSettings:SenderName"] ?? "Your App Name";
        }

        public async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            // Create client with tracking settings disabled
            var client = new SendGridClient(_sendGridApiKey);
            var from = new EmailAddress(_senderEmail, _senderName);
            var to = new EmailAddress(recipientEmail);

            // Create the email message
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent: null, htmlContent: body);

            // Explicitly disable click tracking for this message
            msg.SetClickTracking(false, false);

            var response = await client.SendEmailAsync(msg);

            if (response.StatusCode != System.Net.HttpStatusCode.Accepted && response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                var responseBody = await response.Body.ReadAsStringAsync();
                _logger.LogError("Email sending failed with status code: {StatusCode}. Response Body: {ResponseBody}", response.StatusCode, responseBody);
                throw new InvalidOperationException($"Email sending failed with status code: {response.StatusCode}. Response Body: {responseBody}");
            }

            _logger.LogInformation("Email sent successfully to {RecipientEmail}", recipientEmail);
        }
    }

    public class EmailSettings
    {
        public string SmtpHost { get; set; } = "";
        public int SmtpPort { get; set; }
        public string SenderEmail { get; set; } = "";
        public string SenderName { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
    }
}
