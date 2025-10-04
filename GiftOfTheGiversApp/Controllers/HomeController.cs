using System.Diagnostics;
using GiftOfTheGiversApp.Models;
using Microsoft.AspNetCore.Mvc;

namespace GiftOfTheGiversApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }


        public IActionResult Create()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }
        public IActionResult Dashboard()
        {
            return View();
        }

        public IActionResult DisasterReports()
        {
            return View();
        }

        public IActionResult Donation()
        {
            return View();
        }
        public IActionResult Volunteer()
        {
            return View();
        }
        public IActionResult Index()
        {
            var model = new HomeViewModel
            {
                UserName = TempData["UserName"]?.ToString(),
                UserRole = TempData["UserRole"]?.ToString()
            };
            return View(model);
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
