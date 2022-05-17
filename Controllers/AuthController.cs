namespace my_first_pr.Controllers
{
    [Route("[controller]/[action]")]
    public class AuthController : Controller
    {
        private readonly ILogger _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = "/")
        {
            _logger.LogError(returnUrl);
            return Challenge(new AuthenticationProperties() { RedirectUri = returnUrl });
        }
    }
}