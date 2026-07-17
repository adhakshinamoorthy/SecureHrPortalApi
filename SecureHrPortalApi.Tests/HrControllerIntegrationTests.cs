using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureHrPortalApi.Tests;

public sealed class HrControllerIntegrationTests : IClassFixture<HrApiFactory>
{
    private readonly HttpClient _client;

    public HrControllerIntegrationTests(HrApiFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Login_WithCorrectCredentials_ReturnsValidJwt()
    {
        var response = await LoginAsync("admin", "admin123");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login);
        Assert.False(string.IsNullOrWhiteSpace(login.Token));
        Assert.True(new JwtSecurityTokenHandler().CanReadToken(login.Token));
    }

    [Fact]
    public async Task Login_WithIncorrectCredentials_ReturnsUnauthorized()
    {
        var response = await LoginAsync("admin", "wrong-password");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Profile_WithoutToken_ReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/api/hr/profile");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Profile_WithValidToken_ReturnsOk()
    {
        var token = await GetTokenAsync("employee", "employee123");
        using var request = CreateAuthorizedRequest(HttpMethod.Get, "/api/hr/profile", token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AdminOnly_WithEmployeeRole_ReturnsForbidden()
    {
        var token = await GetTokenAsync("employee", "employee123");
        using var request = CreateAuthorizedRequest(HttpMethod.Get, "/api/hr/admin-only", token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AdminOnly_WithHrAdminRole_ReturnsOk()
    {
        var token = await GetTokenAsync("admin", "admin123");
        using var request = CreateAuthorizedRequest(HttpMethod.Get, "/api/hr/admin-only", token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SeniorData_WithLessThanTwoYearsTenure_ReturnsForbidden()
    {
        var token = await GetTokenAsync("employee", "employee123");
        using var request = CreateAuthorizedRequest(HttpMethod.Get, "/api/hr/senior-data", token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task SeniorData_WithAtLeastTwoYearsTenure_ReturnsOk()
    {
        var token = await GetTokenAsync("admin", "admin123");
        using var request = CreateAuthorizedRequest(HttpMethod.Get, "/api/hr/senior-data", token);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<HttpResponseMessage> LoginAsync(string username, string password)
    {
        return await _client.PostAsJsonAsync("/api/hr/login", new
        {
            username,
            password,
            department = "Operations"
        });
    }

    private async Task<string> GetTokenAsync(string username, string password)
    {
        using var response = await LoginAsync(username, password);
        response.EnsureSuccessStatusCode();

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login);
        return login.Token;
    }

    private static HttpRequestMessage CreateAuthorizedRequest(
        HttpMethod method,
        string path,
        string token)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private sealed record LoginResponse(
        [property: JsonPropertyName("token")] string Token);
}

public sealed class HrApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
    }
}
