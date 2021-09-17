using Microsoft.AspNetCore.Mvc.RazorPages;

namespace my_first_pr.Pages
{
    public class IndexModel : PageModel
    {
        public IReadOnlyList<Issue> Issues { get; set; }
        public Octokit.Language Langs { get; set; }

        public static readonly SearchIssuesRequest HacktoberfestRequest = new SearchIssuesRequest() {
            State = ItemState.Open,
            Labels = new List<string>() {
                "hacktoberfest"
            }
        };

        public static readonly SearchIssuesRequest HacktoberfestFirstRequest = new SearchIssuesRequest() {
            State = ItemState.Open,
            Labels = new List<string>() {
                "hacktoberfest",
                "good-first-issue"
            }
        };

        public static readonly SearchIssuesRequest HacktoberfestEasyRequest = new SearchIssuesRequest() {
            State = ItemState.Open,
            Labels = new List<string>() {
                "hacktoberfest",
                "difficulty:+easy"
            }
        };

        public async Task OnGetAsyc() {}

        public async Task OnPostAsync(string language,string search)
        {
            if (User.Identity is not null && User.Identity.IsAuthenticated)
            {
                string accessToken = await HttpContext.GetTokenAsync("access_token");
                var github = new GitHubClient(new ProductHeaderValue("AspNetCoreGitHubAuth"), new InMemoryCredentialStore(new Credentials(accessToken)));
                var currentSearch = GetSearchIssuesRequest(search);
                if (!String.IsNullOrEmpty(language))
                {
                    currentSearch.Language = (Octokit.Language)(Int32.Parse(language));
                }
                else
                {
                    currentSearch.Language = null;
                }
                Issues = (await github.Search.SearchIssues(currentSearch)).Items;
                currentSearch = null;
            }
        }

        private SearchIssuesRequest GetSearchIssuesRequest(string search)
		{
            switch (search)
			{
                case "HACKTOBERFEST_ISSUES":
                    return HacktoberfestRequest;
                case "HACKTOBERFEST_EASY_ISSUES":
                    return HacktoberfestEasyRequest;
                case "HACKTOBERFEST_FIRST_ISSUES":
                    return HacktoberfestFirstRequest;
                default:
                    return null;
            }
		}
    }

}
