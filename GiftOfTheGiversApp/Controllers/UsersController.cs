using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using GiftOfTheGiversApp.Data;
using GiftOfTheGiversApp.Models;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using GiftOfTheGiversApp.Models;


namespace GiftOfTheGiversApp.Controllers
{
    public class UsersController : Controller
    {
        private readonly ApplicationDbContext _context;

        public UsersController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: Users
        public async Task<IActionResult> Index()
        {
            return View(await _context.Users.ToListAsync());
        }

        // GET: Users/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        // GET: Users/Create (Register Page)
        public IActionResult Create()
        {
            return View();
        }

        // POST: Users/Create (Register)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Email,PasswordHash,Role,FullName,PhoneNumber")] User user)
        {
            // Check if email already exists
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "This email is already registered.");
                return View(user);
            }

            if (string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                ModelState.AddModelError("PasswordHash", "Password is required.");
                return View(user);
            }

            // Hash the password
            user.PasswordHash = HashPassword(user.PasswordHash);
            user.CreatedDate = DateTime.Now;

            _context.Add(user);
            await _context.SaveChangesAsync();

            // Success message
            TempData["SuccessMessage"] = "Registration successful! Please log in with your credentials.";
            return RedirectToAction("Login", "Users");
        }







        // ✅ LOGIN (GET)
        [HttpGet]
        public IActionResult Login()
        {
            return View("~/Views/Users/Login.cshtml"); // use the Login view in Home folder
        }

        // ✅ LOGIN (POST)
        // POST: Users/Login
        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                ViewBag.Error = "Password cannot be empty.";
                return View(model);
            }

            // Hash the entered password
            var hashedPassword = HashPassword(model.Password);

            var user = _context.Users.FirstOrDefault(u => u.Email == model.Email && u.PasswordHash == hashedPassword);

            if (user != null)
            {
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserName", user.FullName ?? "User");
                HttpContext.Session.SetString("UserRole", user.Role ?? "User");

                return RedirectToAction("Dashboard", "Home");
            }

            ViewBag.Error = "Invalid email or password. Please try again.";
            return View(model);
        }






        // ✅ LOGOUT
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Users");
        }

        // GET: Users/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, User editedUser)
        {
            if (id != editedUser.UserId)
                return NotFound();

            if (!ModelState.IsValid)
                return View(editedUser);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == id);
            if (user == null)
                return NotFound();

            // Update only editable fields
            user.Email = editedUser.Email;
            user.FullName = editedUser.FullName;
            user.PhoneNumber = editedUser.PhoneNumber;
            user.Role = editedUser.Role;

            // Only update password if user entered something new
            if (!string.IsNullOrWhiteSpace(editedUser.PasswordHash))
                user.PasswordHash = HashPassword(editedUser.PasswordHash);

            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "User updated successfully!";
            return RedirectToAction(nameof(Index));
        }



        // GET: Users/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var user = await _context.Users
                .Include(u => u.DisasterReports)
                .Include(u => u.Donations)
                .Include(u => u.Volunteers)
                .FirstOrDefaultAsync(u => u.UserId == id);

            if (user != null)
            {
                // ✅ explicitly remove children first
                if (user.DisasterReports.Any())
                    _context.DisasterReports.RemoveRange(user.DisasterReports);

                if (user.Donations.Any())
                    _context.Donations.RemoveRange(user.Donations);

                if (user.Volunteers.Any())
                    _context.Volunteers.RemoveRange(user.Volunteers);

                // now remove user
                _context.Users.Remove(user);

                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool UserExists(int id)
        {
            return _context.Users.Any(e => e.UserId == id);
        }

        // ✅ Password Hashing Helper
        private string HashPassword(string password)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(password);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

    }
}
