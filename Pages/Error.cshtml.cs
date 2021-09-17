using Microsoft.AspNetCore.Mvc.RazorPages;

namespace my_first_pr.Pages;


[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[IgnoreAntiforgeryToken]
public class ErrorModel : PageModel
{
    public Octokit.Language Langs { get; set; }

    public string? RequestId { get; set; }

    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

    private readonly ILogger<ErrorModel> _logger;

    public ErrorModel(ILogger<ErrorModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        RequestId = System.Diagnostics.Activity.Current?.Id ?? HttpContext.TraceIdentifier;
    }
}