using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using SecureHrPortalApi.Security;

var builder = WebApplication.CreateBuilder(args);

// Environment variables are part of the default configuration provider chain.
// Production must use JWT_SIGNING_KEY; the appsettings value is only a local-dev fallback.
var jwtKey = builder.Environment.IsProduction()
    ? builder.Configuration["JWT_SIGNING_KEY"]
    : builder.Configuration["JWT_SIGNING_KEY"] ?? builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
{
    throw new InvalidOperationException(
        builder.Environment.IsProduction()
            ? "JWT_SIGNING_KEY must be configured in production and contain at least 32 characters."
            : "JWT_SIGNING_KEY or Jwt:Key must be configured and contain at least 32 characters.");
}

if (string.IsNullOrWhiteSpace(jwtIssuer))
{
    throw new InvalidOperationException("Jwt:Issuer must be configured.");
}

if (string.IsNullOrWhiteSpace(jwtAudience))
{
    throw new InvalidOperationException("Jwt:Audience must be configured.");
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse();
                await WriteProblemDetailsAsync(
                    context.HttpContext,
                    StatusCodes.Status401Unauthorized,
                    "Unauthorized",
                    "A valid bearer token is required.");
            },
            OnForbidden = context =>
            {
                return WriteProblemDetailsAsync(
                    context.HttpContext,
                    StatusCodes.Status403Forbidden,
                    "Forbidden",
                    "You do not have permission to access this resource.");
            }
        };
    });

builder.Services.AddSingleton<IAuthorizationHandler, MinimumTenureHandler>();
builder.Services.AddSingleton<TokenGenerator>();
builder.Services.AddControllers();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HRAdmin", policy => policy.RequireRole("HRAdmin"));
    options.AddPolicy("Employee", policy => policy.RequireRole("Employee"));
    options.AddPolicy(HrPolicyNames.SeniorStaffOnly, policy =>
        policy.AddRequirements(new MinimumTenureRequirement(2)));
    options.AddPolicy(HrPolicyNames.PayrollAccess, policy =>
    {
        policy.RequireRole("HRAdmin");
        policy.AddRequirements(new MinimumTenureRequirement(1));
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter a valid JWT bearer token."
    });

    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference("Bearer", document, null),
            new List<string>()
        }
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

static Task WriteProblemDetailsAsync(HttpContext httpContext, int status, string title, string detail)
{
    httpContext.Response.StatusCode = status;
    httpContext.Response.ContentType = "application/problem+json";

    return httpContext.Response.WriteAsJsonAsync(new ProblemDetails
    {
        Status = status,
        Title = title,
        Detail = detail,
        Type = $"https://httpstatuses.com/{status}"
    });
}

public partial class Program { }
