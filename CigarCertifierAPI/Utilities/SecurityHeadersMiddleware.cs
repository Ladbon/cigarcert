// SecurityHeadersMiddleware.cs
namespace CigarCertifierAPI.Utilities
{
    /// <summary>
    /// Middleware to add security-related HTTP headers to responses.
    /// </summary>
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Content Security Policy
            if (!context.Response.Headers.ContainsKey("Content-Security-Policy"))
            {
                context.Response.Headers.Append("Content-Security-Policy",
                    "default-src 'self'; " +
                    "script-src 'self' https://cdnjs.cloudflare.com; " +
        "style-src 'self' 'unsafe-inline'; " +  // Add 'unsafe-inline' here
                    "img-src 'self' data:;");
            }

            // Prevent MIME type sniffing
            if (!context.Response.Headers.ContainsKey("X-Content-Type-Options"))
            {
                context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
            }

            // Clickjacking protection
            if (!context.Response.Headers.ContainsKey("X-Frame-Options"))
            {
                context.Response.Headers.Append("X-Frame-Options", "DENY");
            }

            // Enable XSS protection
            if (!context.Response.Headers.ContainsKey("X-XSS-Protection"))
            {
                context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
            }

            await _next(context);
        }
    }
}
