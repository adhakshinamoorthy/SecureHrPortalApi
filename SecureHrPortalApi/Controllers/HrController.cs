using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureHrPortalApi.Models;
using SecureHrPortalApi.Security;

namespace SecureHrPortalApi.Controllers;

[ApiController]
[Route("api/hr")]
public sealed class HrController(TokenGenerator tokenGenerator) : ControllerBase
{
    private static readonly MockUser[] Users =
    [
        new("admin", "admin123", "HRAdmin", "Human Resources", DateTime.UtcNow.AddYears(-3)),
        new("employee", "employee123", "Employee", "Operations", DateTime.UtcNow.AddMonths(-6))
    ];

    private readonly TokenGenerator _tokenGenerator = tokenGenerator
        ?? throw new ArgumentNullException(nameof(tokenGenerator));

    [HttpPost("login")]
    [AllowAnonymous]
    public ActionResult<object> Login(UserCredentials? credentials)
    {
        if (credentials is null)
        {
            return Unauthorized(CreateProblemDetails(
                StatusCodes.Status401Unauthorized,
                "Authentication failed.",
                "Credentials are required."));
        }

        var user = Users.FirstOrDefault(candidate =>
            string.Equals(candidate.Username, credentials.Username, StringComparison.Ordinal)
            && string.Equals(candidate.Password, credentials.Password, StringComparison.Ordinal));

        if (user is null)
        {
            return Unauthorized(CreateProblemDetails(
                StatusCodes.Status401Unauthorized,
                "Authentication failed.",
                "The supplied username or password is invalid."));
        }

        var token = _tokenGenerator.GenerateToken(
            user.Username,
            [user.Role],
            user.Department,
            user.HireDate);

        return Ok(new { token });
    }

    [HttpGet("profile")]
    [Authorize]
    public ActionResult<object> Profile()
    {
        var username = User.FindFirstValue(ClaimTypes.Name) ?? User.Identity?.Name;
        var roles = User.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToArray();
        var department = User.FindFirstValue("department");

        return Ok(new
        {
            username,
            roles,
            department
        });
    }

    [HttpGet("admin-only")]
    [Authorize(Roles = "HRAdmin")]
    public ActionResult<object> AdminOnly() => Ok(new
    {
        message = "HR admin access confirmed."
    });

    [HttpGet("senior-data")]
    [Authorize(Policy = HrPolicyNames.SeniorStaffOnly)]
    public ActionResult<object> SeniorData() => Ok(new
    {
        data = "Confidential senior staff HR data."
    });

    [HttpGet("payroll")]
    [Authorize(Policy = HrPolicyNames.PayrollAccess)]
    public ActionResult<object> Payroll() => Ok(new
    {
        data = "Confidential payroll data."
    });

    private static ProblemDetails CreateProblemDetails(int status, string title, string detail) => new()
    {
        Status = status,
        Title = title,
        Detail = detail,
        Type = $"https://httpstatuses.com/{status}"
    };

    private sealed record MockUser(
        string Username,
        string Password,
        string Role,
        string Department,
        DateTime HireDate);
}
