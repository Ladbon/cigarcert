using ActiveLogin.Authentication.BankId.AspNetCore.Auth;
using ActiveLogin.Authentication.BankId.Core;
using ActiveLogin.Authentication.BankId.QrCoder;
using ActiveLogin.Authentication.BankId.UaParser;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.CookiePolicy;
using ActiveLogin.Authentication.BankId.AspNetCore;
using ActiveLogin.Authentication.BankId.AzureMonitor;
using ActiveLogin.Authentication.BankId.AspNetCore.Sign;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var configuration = builder.Configuration;
var environment = builder.Environment;

// Add services to the container
builder.Services.AddControllers();

// Add telemetry
services.AddApplicationInsightsTelemetry(configuration);

// Configure cookie policy
services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.HttpOnly = HttpOnlyPolicy.Always;
    options.Secure = CookieSecurePolicy.Always;
});

// Add Active Login - BankID
services
    .AddBankId(bankId =>
    {
        bankId.AddDebugEventListener();
        bankId.AddApplicationInsightsEventListener(options =>
        {
            options.LogUserPersonalIdentityNumber = false;
            options.LogUserPersonalIdentityNumberHints = true;

            options.LogUserNames = false;

            options.LogUserBankIdIssueDate = false;

            options.LogDeviceIpAddress = false;
            options.LogDeviceUniqueHardwareId = false;
        });

        bankId.UseQrCoderQrCodeGenerator();
        bankId.UseUaParserDeviceDetection();

        bankId.AddCustomBrowserByUserAgent(userAgent => userAgent.Contains("Instagram"), "instagram://");
        bankId.AddCustomBrowserByUserAgent(userAgent => userAgent.Contains("FBAN") || userAgent.Contains("FBAV"), "fb://");

        if (configuration.GetValue("ActiveLogin:BankId:UseSimulatedEnvironment", false))
        {
            bankId.UseSimulatedEnvironment();
        }
        else if (configuration.GetValue("ActiveLogin:BankId:UseTestEnvironment", false))
        {
            bankId.UseTestEnvironment();
        }
        else
        {
          //  bankId.UseProductionEnvironment()
           //     .UseClientCertificateFromAzureKeyVault(configuration.GetSection("ActiveLogin:BankId:ClientCertificate"));
        }
    });

// Add Active Login - Auth
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie()
    .AddBankIdAuth(bankId =>
    {
        bankId.AddSameDevice(BankIdAuthDefaults.SameDeviceAuthenticationScheme, "BankID (SameDevice)", options => { });
        bankId.AddOtherDevice(BankIdAuthDefaults.OtherDeviceAuthenticationScheme, "BankID (OtherDevice)", options => { });
    });

// Add Active Login - Sign
services.AddBankIdSign(bankId =>
{
    bankId.AddSameDevice(BankIdSignDefaults.SameDeviceConfigKey, "BankID (SameDevice)", options => { });
    bankId.AddOtherDevice(BankIdSignDefaults.OtherDeviceConfigKey, "BankID (OtherDevice)", options => { });
});

// Add Authorization
builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});

// Add MVC
services.AddControllersWithViews();

// Add BankID Authentication
builder.Services.AddBankId(bankId => {
    bankId.AddDebugEventListener();
    bankId.UseQrCoderQrCodeGenerator();
    bankId.UseUaParserDeviceDetection();
    bankId.UseSimulatedEnvironment();
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddBankIdAuth(bankId =>
         {
             bankId.AddSameDevice();
             bankId.AddOtherDevice();
         })
        .AddCookie();
builder.Services.AddApplicationInsightsTelemetry();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

