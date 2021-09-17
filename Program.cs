using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
Console.WriteLine(builder.Environment);
builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", true);
builder.Services.AddAuthentication( options => {
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Github";
})
    .AddCookie(options => {
        options.Cookie.SameSite = SameSiteMode.Lax;
    })
    .AddOAuth("Github", options => {
        options.ClientId = builder.Configuration["GitHub:ClientId"] ?? Environment.GetEnvironmentVariable("GITHUB_CLIENT_ID");
        options.ClientSecret = builder.Configuration["GitHub:ClientSecret"] ?? Environment.GetEnvironmentVariable("GITHUB_CLIENT_SECRET");
        options.CallbackPath = new PathString("/signin-github");
        options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        options.TokenEndpoint = "https://github.com/login/oauth/access_token";
        options.UserInformationEndpoint = "https://api.github.com/user";
        options.SaveTokens = true;
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        options.ClaimActions.MapJsonKey("urn:github:login", "login");
        options.ClaimActions.MapJsonKey("urn:github:url", "html_url");
        options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();
                var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                context.RunClaimActions(json.RootElement);
            }
        };
    });

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapRazorPages();

app.MapControllers();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();
