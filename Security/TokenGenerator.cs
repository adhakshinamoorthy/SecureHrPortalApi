using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SecureHrPortalApi.Security;

public sealed class TokenGenerator
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly SymmetricSecurityKey _signingKey;
    private readonly int _expiryMinutes;

    public TokenGenerator(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var key = configuration["JWT_SIGNING_KEY"] ?? configuration["Jwt:Key"];
        if (string.IsNullOrWhiteSpace(key) || key.Length < 32)
        {
            throw new InvalidOperationException(
                "JWT_SIGNING_KEY or Jwt:Key must be configured and contain at least 32 characters.");
        }

        _issuer = GetRequiredSetting(configuration, "Jwt:Issuer");
        _audience = GetRequiredSetting(configuration, "Jwt:Audience");

        if (!int.TryParse(
                configuration["Jwt:ExpiryMinutes"],
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out _expiryMinutes)
            || _expiryMinutes <= 0)
        {
            throw new InvalidOperationException("Jwt:ExpiryMinutes must be a positive integer.");
        }

        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    }

    public string GenerateToken(
        string username,
        IEnumerable<string> roles,
        string department,
        DateTime hireDate)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username is required.", nameof(username));
        }

        ArgumentNullException.ThrowIfNull(roles);

        var roleList = roles.ToArray();
        if (roleList.Length == 0 || roleList.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("At least one non-empty role is required.", nameof(roles));
        }

        if (string.IsNullOrWhiteSpace(department))
        {
            throw new ArgumentException("Department is required.", nameof(department));
        }

        if (hireDate == default)
        {
            throw new ArgumentException("Hire date is required.", nameof(hireDate));
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new("department", department),
            new("hireDate", hireDate.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))
        };

        claims.AddRange(roleList.Select(role => new Claim(ClaimTypes.Role, role)));

        // For production key rotation, replace this symmetric key and HMAC-SHA256
        // credential with RSA (RS256) or ECDSA (ES256) credentials backed by a key store.
        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_expiryMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GetRequiredSetting(IConfiguration configuration, string key)
    {
        var value = configuration[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{key} must be configured.");
        }

        return value;
    }
}
