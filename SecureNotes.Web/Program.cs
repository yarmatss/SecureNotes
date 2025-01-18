using Ganss.Xss;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Web.Data;
using SecureNotes.Web.Models;
using SecureNotes.Web.Services;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
        theme: AnsiConsoleTheme.Code)
    .CreateLogger();

try
{
    Log.Information("Starting application");

    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseSerilog();

    builder.WebHost.ConfigureKestrel(options =>
    {
        options.AddServerHeader = false;
    });

    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
        .SetApplicationName("SecureNotes")
        .ProtectKeysWithCertificate(
            X509Certificate2.CreateFromPemFile(
                "/app/certs/webapp.chained.crt",
                "/app/certs/webapp.key"));

    var nginxIPAddress = IPAddress.Parse(Environment.GetEnvironmentVariable("NGINX_IP_ADDRESS")!);
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.KnownProxies.Add(nginxIPAddress);
    });

    builder.Services.Configure<HstsOptions>(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(365);
    });

    // Add services to the container.
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString, sqlServerOptions =>
        sqlServerOptions.EnableRetryOnFailure()));

    builder.Services.AddDefaultIdentity<User>(options => {
        options.SignIn.RequireConfirmedAccount = false;
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;
        options.User.RequireUniqueEmail = false;
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";

        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredUniqueChars = 3;

        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>();
    builder.Services.AddRazorPages();

    // Register application services
    builder.Services.AddScoped<INoteService, NoteService>();
    builder.Services.AddScoped<ISigningService, SigningService>();
    builder.Services.AddScoped<IEncryptionService, EncryptionService>();
    builder.Services.AddScoped<IMarkdownService, MarkdownService>();
    builder.Services.AddScoped<IHtmlSanitizer>(_ => {
        var sanitizer = new HtmlSanitizer();
        sanitizer.AllowedTags.Clear();
        sanitizer.AllowedAttributes.Clear();
        sanitizer.AllowedSchemes.Clear();

        var tags = new[] { "p", "br", "strong", "em", "h1", "h2", "h3", "h4", "h5", "a", "img" };
        foreach (var tag in tags)
        {
            sanitizer.AllowedTags.Add(tag);
        }

        var attributes = new[] { "href", "src", "alt" };
        foreach (var attr in attributes)
        {
            sanitizer.AllowedAttributes.Add(attr);
        }

        sanitizer.AllowedSchemes.Add("https");

        return sanitizer;
    });

    builder.Services.Configure<SecurityStampValidatorOptions>(options =>
    {
        options.ValidationInterval = TimeSpan.FromMinutes(5);
    });

    builder.Services.AddHttpsRedirection(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status301MovedPermanently;
        options.HttpsPort = 443;
    });

    // Add rate limiting
    builder.Services.AddRateLimiter(options => {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: context.User.Identity?.Name ?? context.Request.Headers.Host.ToString(),
                factory: partition => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,
                    PermitLimit = 100,
                    QueueLimit = 0,
                    Window = TimeSpan.FromMinutes(1)
                }));
    });

    var app = builder.Build();

    using (var scope = app.Services.CreateScope())
    {
        await Task.Delay(10000); // Wait for SQL Server to start

        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        if (dbContext.Database.GetPendingMigrations().Any())
        {
            dbContext.Database.Migrate();
        }
    }

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseMigrationsEndPoint();
    }
    else
    {
        app.UseExceptionHandler("/Error");
    }

    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    });

    // Content-Security-Policy
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Remove("Server");
        context.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        context.Response.Headers.Append(
            "Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' https: data:; " +
            "font-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-src 'none'; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "upgrade-insecure-requests;"
        );
        await next();
    });

    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
    app.UseHttpsRedirection();

    app.UseRouting();
    

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapStaticAssets();
    app.MapRazorPages()
       .WithStaticAssets();

    app.MapGet("/", context =>
    {
        context.Response.Redirect("/Notes/MyNotes");
        return Task.CompletedTask;
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}