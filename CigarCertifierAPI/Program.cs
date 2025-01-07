using System.IdentityModel.Tokens.Jwt;
using System.Text;
using CigarCertifierAPI.Configurations;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Services;
using CigarCertifierAPI.Utilities;
using DotNetEnv;
using Hangfire;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    private static void Main(string[] args)
    {
        // Load environment variables from .env file
        Env.Load();

        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddEnvironmentVariables();

        // Logging configuration
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddDebug();

        IServiceCollection services = builder.Services;
        ConfigurationManager configuration = builder.Configuration;

        // Register JwtSettings
        services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
        services.AddSingleton(provider =>
        {
            var jwtSettings = provider.GetRequiredService<IOptions<JwtSettings>>().Value;
            jwtSettings.Secret = JwtHelper.GetJwtSecret(configuration);
            return jwtSettings;
        });

        // Register LoggerService
        services.AddSingleton<LoggerService>();

        builder.Services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("/root/.aspnet/DataProtection-Keys"))
            .SetApplicationName("CigarCertifierAPI");

        // Add MVC controllers
        services.AddControllers();

        // Add Hangfire services
        services.AddHangfire(config => config
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseSqlServerStorage(configuration.GetConnectionString("DefaultConnection")));

        // Add Hangfire server
        services.AddHangfireServer();

        // Add EF Core
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        // JWT configuration
        JwtSettings jwtSettings = configuration.GetSection("Jwt").Get<JwtSettings>()
                                    ?? throw new InvalidOperationException("JWT settings are not configured properly.");
        jwtSettings.Secret = JwtHelper.GetJwtSecret(configuration);
        services.AddSingleton(jwtSettings);

        string jwtSecret = jwtSettings.Secret
           ?? throw new InvalidOperationException("JWT_SECRET is not set.");
        Console.WriteLine($"JWT_SECRET: {jwtSecret}");

        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtSecret));
        SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);
        IdentityModelEventSource.ShowPII = true;

        // Add Authentication
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // Force the use of JwtSecurityTokenHandler for validation
                options.UseSecurityTokenValidators = true;
                options.TokenHandlers.Clear();
                options.TokenHandlers.Add(new JwtSecurityTokenHandler());

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = key,
                    // Ensure the algorithm matches the one used in token generation
                    RequireSignedTokens = true,
                    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
                };

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        ILogger logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        ApplicationDbContext dbContext = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();

                        if (context.SecurityToken is JwtSecurityToken jwtToken)
                        {
                            string token = jwtToken.RawData;
                            logger.LogInformation("Validating token: {Token}", token);

                            if (!await TokenHelper.IsTokenValid(token, dbContext))
                            {
                                logger.LogWarning("Token is invalid or blacklisted: {Token}", token);
                                context.Fail("This token is invalid or revoked.");
                            }
                            else
                            {
                                logger.LogInformation("Token validated: {Token}", token);
                            }
                        }
                        else
                        {
                            logger.LogWarning("Security token is not a valid JwtSecurityToken.");
                            context.Fail("Invalid token type.");
                        }
                    },
                    OnAuthenticationFailed = context =>
                    {
                        ILogger logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        logger.LogError("Authentication failed: {Exception}", context.Exception);
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorization();

        WebApplication app = builder.Build();

        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        // Use Hangfire Dashboard (Optional)
        app.UseHangfireDashboard();

        // Schedule cleanup job
        RecurringJob.AddOrUpdate<TokenCleanupService>(
            "CleanupExpiredTokens",
            service => service.CleanupExpiredTokensAsync(),
            Cron.Hourly);

        app.MapControllers();
        app.Run();
    }
}
