namespace SecureHrPortalApi.Models;

/// <summary>
/// Represents the credentials submitted for a user.
/// </summary>
/// <remarks>
/// Field-backed properties are used instead of primary-constructor parameters so
/// validation runs whenever a property is assigned, including during object
/// initializers and future model binding. This keeps the validation close to the
/// mutable state and avoids relying solely on constructor call sites or
/// DataAnnotations.
/// </remarks>
public record class UserCredentials
{
    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when the username is missing or is not between 3 and 50 characters.
    /// </exception>
    public required string Username
    {
        get;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length is < 3 or > 50)
            {
                throw new ArgumentException("Username must be between 3 and 50 characters.", nameof(Username));
            }

            field = value;
        }
    }

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when the password is missing or contains fewer than 8 characters.
    /// </exception>
    public required string Password
    {
        get;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < 8)
            {
                throw new ArgumentException("Password must contain at least 8 characters.", nameof(Password));
            }

            field = value;
        }
    }

    /// <summary>
    /// Gets or sets the optional department used later for tenure and policy checks.
    /// </summary>
    public string? Department
    {
        get;
        set
        {
            field = value;
        }
    }
}
