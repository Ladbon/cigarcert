using System.IdentityModel.Tokens.Jwt;
using System.Text;
using CigarCertifierAPI.Configurations;
using CigarCertifierAPI.Data;
using CigarCertifierAPI.Services;
using CigarCertifierAPI.Utilities;
using DotNetEnv;
using Hangfire;
using Hangfire.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Reflection;

internal class Program
{
    private static void Main(string[] args)
    {
        // Load environment variables from .env file
        Env.Load();

        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddEnvironmentVariables();

        // Remove default logging providers
        builder.Logging.ClearProviders();

        // Configure Serilog
        Log.Logger = new LoggerConfiguration()
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
            .CreateLogger();

        // Use Serilog
        builder.Host.UseSerilog();

        IServiceCollection services = builder.Services;
        ConfigurationManager configuration = builder.Configuration;

        // Swagger configuration with XML comments
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            string xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            string xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            options.IncludeXmlComments(xmlPath);

            // If your models are in a different assembly:
            // var xmlModelFile = "CigarCertifierAPI.xml";
            // var xmlModelPath = Path.Combine(AppContext.BaseDirectory, xmlModelFile);
            // options.IncludeXmlComments(xmlModelPath);
        });

        // Register JwtSettings
        services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        services.AddSingleton(provider =>
        {
            JwtSettings jwtSettings = provider.GetRequiredService<IOptions<JwtSettings>>().Value;
            jwtSettings.Secret = JwtHelper.GetJwtSecret(configuration);
            return jwtSettings;
        });

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", builder =>
            {
                builder
                    .WithOrigins("http://localhost:4200")
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });

        // Register LoggerService
        services.AddSingleton<LoggerService>();

        // Data Protection
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("/root/.aspnet/DataProtection-Keys"))
            .SetApplicationName("CigarCertifierAPI");

        // Add MVC controllers
        services.AddControllers();

        // Add Hangfire services and server
        services.AddHangfire(config => config
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseSqlServerStorage(configuration.GetConnectionString("DefaultConnection")));

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
                        ILogger<Program> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
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
                        ILogger<Program> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        logger.LogError(context.Exception, "Authentication failed.");
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorization();

        WebApplication app = builder.Build();

        // Use Serilog request logging
        app.UseSerilogRequestLogging();

        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseCors("CorsPolicy");

        app.UseSwagger();
        app.UseSwaggerUI();

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
