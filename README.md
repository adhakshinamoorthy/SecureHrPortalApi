# SecureHrPortalApi

SecureHrPortalApi is a .NET 10 minimal-hosting Web API scaffold for a secure HR portal. It demonstrates a small, understandable authentication and authorization pipeline that can later be connected to a real identity provider, HR database, and Azure-hosted infrastructure.

The project is intentionally focused on the security flow:

```text
HTTP request
    -> JWT Bearer authentication
    -> role/policy authorization
    -> controller endpoint
    -> response
```

## What was built

### Project foundation

- Targets `net10.0`.
- Uses top-level `Program.cs` and minimal hosting.
- Enables nullable reference types and implicit usings.
- Includes JWT Bearer authentication, authorization, Swagger, and token packages.
- Uses `appsettings.json` for non-secret JWT settings such as issuer, audience, and expiry.

### Configuration and secret handling

The signing key is read through `IConfiguration`:

1. Production requires `JWT_SIGNING_KEY`.
2. Development can use `JWT_SIGNING_KEY` from user-secrets.
3. The `Jwt:Key` value in `appsettings.json` is only a local placeholder.

The key must be at least 32 characters because it is used for HMAC-SHA256 signing. Real signing keys must never be committed to source control.

### `Models/UserCredentials.cs`

`UserCredentials` is a C# 14 `record class` with `Username`, `Password`, and optional `Department` properties. Its setters use the C# 14 `field` contextual keyword:

- `Username` must contain 3–50 characters.
- `Password` must contain at least 8 characters.
- Invalid assignments throw `ArgumentException` immediately.

This demonstrates validation close to the mutable property state. It also works with object initializers and model binding, rather than validating only when a primary constructor is called.

### `Security/TokenGenerator.cs`

`TokenGenerator` is registered with dependency injection and creates signed JWTs. It:

- Reads issuer, audience, expiry, and signing-key settings from `IConfiguration`.
- Uses `SymmetricSecurityKey` and HMAC-SHA256.
- Adds the username, role claims, `department`, and `hireDate` claims.
- Rejects missing or invalid configuration with `InvalidOperationException`.
- Documents how production key rotation could move to RSA/RS256 or ECDSA/ES256 keys.

For a production system with independent services or frequent key rotation, asymmetric signing is usually preferable: the issuer keeps the private key, while APIs validate tokens with a public key.

### `Security/HrPolicies.cs`

`MinimumTenureRequirement` and `MinimumTenureHandler` demonstrate custom policy authorization:

- The handler reads the `hireDate` claim from the authenticated `ClaimsPrincipal`.
- It calculates completed tenure years against `DateTime.UtcNow`.
- Missing, malformed, or unusable dates fail the requirement without throwing.
- `HrPolicyNames` centralizes policy names to avoid string duplication.

The configured policies are:

| Policy | Rule |
| --- | --- |
| `HRAdmin` | Requires the `HRAdmin` role |
| `Employee` | Requires the `Employee` role |
| `SeniorStaffOnly` | Requires at least 2 completed years |
| `PayrollAccess` | Requires `HRAdmin` and at least 1 completed year |

The tenure handler is registered as a singleton because it is stateless and does not depend on request-scoped services.

### `Controllers/HrController.cs`

The controller is exposed at `api/hr` and currently uses a hardcoded mock user store for learning and integration testing:

| Username | Password | Role | Hire date |
| --- | --- | --- | --- |
| `admin` | `admin123` | `HRAdmin` | 3 years ago |
| `employee` | `employee123` | `Employee` | 6 months ago |

The mock store is deliberately not production authentication. In a real system, credentials should be validated by an identity provider or a properly hashed password store.

## API endpoints

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/hr/login` | Anonymous | Validates mock credentials and returns a JWT |
| `GET` | `/api/hr/profile` | Authenticated | Returns username, roles, and department claims |
| `GET` | `/api/hr/admin-only` | `HRAdmin` role | Returns an admin confirmation |
| `GET` | `/api/hr/senior-data` | `SeniorStaffOnly` policy | Returns mock sensitive HR data |
| `GET` | `/api/hr/payroll` | `PayrollAccess` policy | Returns mock payroll data |

Unauthorized and forbidden responses use `ProblemDetails`-style JSON with `application/problem+json`.

## Run locally

From the repository root:

```powershell
dotnet restore
dotnet run
```

Swagger is available at:

```text
http://localhost:<port>/swagger
```

Use the Swagger **Authorize** button and paste only the raw JWT value. Swagger UI adds the `Bearer` prefix automatically. Do not enter `Bearer ` yourself.

```text
<jwt-token>
```

The development placeholder in `appsettings.json` allows the sample to start, but user-secrets are recommended even for local development.

## Local secret configuration

Initialize user-secrets and set a sufficiently long signing key:

```powershell
dotnet user-secrets init
dotnet user-secrets set "JWT_SIGNING_KEY" "replace-with-a-local-development-key-at-least-32-characters"
dotnet run
```

The ASP.NET Core Development environment loads user-secrets through the normal configuration provider chain. User-secrets override the appsettings placeholder and are stored outside the repository.

## Azure configuration

For an Azure deployment behind Azure AD-integrated infrastructure:

1. Store the JWT signing key in Azure Key Vault.
2. Create an Azure App Configuration key named `JWT_SIGNING_KEY` as a Key Vault reference.
3. Use this Key Vault reference payload:

   ```json
   {"uri":"https://<vault-name>.vault.azure.net/secrets/JWT_SIGNING_KEY"}
   ```

4. Set the content type to `application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8`.
5. Grant the deployed managed identity permission to read the App Configuration key and the Key Vault secret.
6. Load Azure App Configuration before the application is built so it participates in the `IConfiguration` provider chain.

The API then reads the resolved `JWT_SIGNING_KEY` without putting the secret in source code or `appsettings.json`. Key Vault should be the system of record for rotation and auditing.

## Try the API manually

Get a token:

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:<port>/api/hr/login" `
  -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123","department":"Human Resources"}'

$token = $login.token
```

Call a protected endpoint:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:<port>/api/hr/profile" `
  -Headers @{ Authorization = "Bearer $token" }
```

Expected authorization behavior:

- `employee` receives `403` from `/api/hr/admin-only`.
- `employee` receives `403` from `/api/hr/senior-data` because tenure is under two years.
- `admin` receives `200` from both of those endpoints.
- `employee` cannot use `/api/hr/payroll` because it lacks the `HRAdmin` role and the required tenure.

## Run the integration tests

The test project uses xUnit and `WebApplicationFactory<Program>` to host the actual API in memory:

```powershell
dotnet test .\SecureHrPortalApi.Tests\SecureHrPortalApi.Tests.csproj
```

The tests obtain real JWTs from `/api/hr/login`; they do not hand-craft tokens. They cover:

- Successful and failed login.
- Profile access with and without a token.
- HR admin role enforcement.
- Senior-tenure policy enforcement.

Using the real login flow makes these tests useful as regression tests for configuration, token generation, authentication, claims, and authorization together.

## Suggested production extensions

This scaffold is a learning foundation, not a complete production HR system. Typical next steps are:

- Replace the mock login store with Microsoft Entra ID/OIDC or a secure identity service.
- Remove plaintext mock passwords and use managed identity or an external identity provider.
- Replace mock HR and payroll responses with database-backed services.
- Add audit logging for authentication and sensitive HR access.
- Add rate limiting, refresh-token strategy, token revocation, and abuse monitoring.
- Use RSA/ES256 signing with a key identifier (`kid`) and a published key set for rotation.
- Add integration-test configuration isolated from production secrets.
- Add API versioning, health checks, structured logging, and deployment automation.
