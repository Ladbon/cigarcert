// Program.cs
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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Reflection;
using System.Threading.RateLimiting;

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
        });

        // Register JwtSettings
        services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        services.AddSingleton(provider =>
        {
            JwtSettings jwtSettings = provider.GetRequiredService<IOptions<JwtSettings>>().Value;
            jwtSettings.Secret = JwtHelper.GetJwtSecret(configuration);
            return jwtSettings;
        });

        // Register LoggerService
        services.AddSingleton<LoggerService>();

        // Register EmailService with scoped lifetime and ILogger
        services.AddScoped<EmailService>();

        // Add Serilog logging
        services.AddLogging(loggingBuilder =>
        {
            loggingBuilder.AddSerilog(dispose: true);
        });

        // Data Protection
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("DataProtection-Keys"))
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
        services.AddScoped<TokenCleanupService>();
        services.AddLogging();

        // **Add Rate Limiting Services**
        services.AddRateLimiter(options =>
        {
            // Define Login Policy
            options.AddPolicy("LoginPolicy", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    factory: partition => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 50, // Max 5 attempts
                        Window = TimeSpan.FromMinutes(15), // Per 15 minutes
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                    }));

            // Global Rate Limiter
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: "global",
                    factory: partition => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 60,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                    });
            });

            // Specific Rate Limiter Policy
            options.AddPolicy("EndpointPolicy", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: "endpoint_policy",
                    factory: partition => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 100,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                    }));
        });

        services.Configure<CookiePolicyOptions>(options =>
        {
            options.MinimumSameSitePolicy = SameSiteMode.Strict;
        });

        // JWT configuration
        JwtSettings jwtSettings = configuration.GetSection("Jwt").Get<JwtSettings>()
                                    ?? throw new InvalidOperationException("JWT settings are not configured properly.");
        jwtSettings.Secret = JwtHelper.GetJwtSecret(configuration);
        services.AddSingleton(jwtSettings);

        string jwtSecret = jwtSettings.Secret
            ?? throw new InvalidOperationException("JWT_SECRET is not set.");

        SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(jwtSecret));
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
                    RequireSignedTokens = true
                };

                options.Events = new JwtBearerEvents
                {

                    OnMessageReceived = context =>
                    {
                        // Check if token exists in the cookie
                        string? token = context.Request.Cookies["token"];
                        if (!string.IsNullOrEmpty(token))
                        {
                            // Set the token for the middleware to validate
                            context.Token = token;
                        }

                        return Task.CompletedTask;
                    },

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

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", builder =>
            {
                builder
                    .WithOrigins(
                        "http://localhost:4200",
                        "https://localhost:4200",
                        "http://your-production-domain.com",
                        "https://your-production-domain.com"
                    )
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });

        // **Register HSTS Services**
        if (!builder.Environment.IsDevelopment())
        {
            services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(365);
            });
        }

        WebApplication app = builder.Build();

        if (!app.Environment.IsDevelopment())
        {
            // **Apply HSTS Middleware Without Arguments**
            app.UseHsts();
        }

        // Use Serilog request logging
        app.UseSerilogRequestLogging();

        app.UseHttpsRedirection();
        app.UseRouting();

        // Apply CORS policy here
        app.UseCors("CorsPolicy");

        // Add Security Headers Middleware
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // **Apply Rate Limiting Middleware**
        app.UseRateLimiter();

        app.UseAuthentication();
        app.UseAuthorization();

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
