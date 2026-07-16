using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace SecureHrPortalApi.Security;

public sealed class MinimumTenureRequirement(int minimumYears) : IAuthorizationRequirement
{
    public int MinimumYears { get; } = minimumYears >= 0
        ? minimumYears
        : throw new ArgumentOutOfRangeException(nameof(minimumYears), "Minimum years cannot be negative.");
}

public sealed class MinimumTenureHandler : AuthorizationHandler<MinimumTenureRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumTenureRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return Task.CompletedTask;
        }

        var hireDateClaim = context.User.FindFirst("hireDate");
        if (hireDateClaim is null
            || !DateTime.TryParse(
                hireDateClaim.Value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var hireDate))
        {
            return Task.CompletedTask;
        }

        try
        {
            var now = DateTime.UtcNow;
            var normalizedHireDate = hireDate.ToUniversalTime();
            var tenureYears = now.Year - normalizedHireDate.Year;
            if (normalizedHireDate.AddYears(tenureYears).Date > now.Date)
            {
                tenureYears--;
            }

            if (tenureYears >= requirement.MinimumYears)
            {
                context.Succeed(requirement);
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            // An unrepresentable date cannot establish tenure, so leave the
            // requirement unsatisfied without failing authorization evaluation.
        }

        return Task.CompletedTask;
    }
}

public static class HrPolicyNames
{
    public const string SeniorStaffOnly = "SeniorStaffOnly";
    public const string PayrollAccess = "PayrollAccess";
}
