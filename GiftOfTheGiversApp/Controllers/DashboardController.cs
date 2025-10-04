using Microsoft.AspNetCore.Mvc;

namespace GiftOfTheGiversApp.Controllers
{
    public class DashboardController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
