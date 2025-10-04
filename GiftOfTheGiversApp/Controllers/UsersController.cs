using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using GiftOfTheGiversApp.Data;
using GiftOfTheGiversApp.Models;
using Microsoft.AspNetCore.Http;

namespace GiftOfTheGiversApp.Controllers
{
    public class UsersController : Controller
    {
        private readonly ApplicationDbContext _context;

        public UsersController(ApplicationDbContext context)
        {
            _context = context;
        }

        // =============================
        // PASSWORD HASHING UTILITY
        // =============================
        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }

        // =============================
        // USER LIST & DETAILS (ADMIN)
        // =============================
        public async Task<IActionResult> Index()
        {
            return View(await _context.Users.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();

            var user = await _context.Users.FirstOrDefaultAsync(m => m.UserId == id);
            if (user == null) return NotFound();

            return View(user);
        }

        // =============================
        // REGISTER USER
        // =============================
        [HttpGet]
        public IActionResult Create() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Email,PasswordHash,Role,FullName,PhoneNumber")] User user)
        {
            if (await _context.Users.AnyAsync(u => u.Email == user.Email))
            {
                ModelState.AddModelError("Email", "This email is already registered.");
                return View(user);
            }

            if (string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                ModelState.AddModelError("PasswordHash", "Password is required.");
                return View(user);
            }

            user.PasswordHash = HashPassword(user.PasswordHash);
            user.CreatedDate = DateTime.Now;

            _context.Add(user);
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "Registration successful! Please log in.";
            return RedirectToAction("Login");
        }

        // =============================
        // LOGIN / LOGOUT
        // =============================
        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                ViewBag.Error = "Password cannot be empty.";
                return View(model);
            }

            var hashedPassword = HashPassword(model.Password);
            var user = _context.Users.FirstOrDefault(u => u.Email == model.Email && u.PasswordHash == hashedPassword);

            if (user == null)
            {
                ViewBag.Error = "Invalid email or password.";
                return View(model);
            }

            HttpContext.Session.SetString("UserEmail", user.Email);
            HttpContext.Session.SetString("UserName", user.FullName ?? "User");
            HttpContext.Session.SetString("UserRole", user.Role ?? "User");

            return RedirectToAction("Dashboard", "Home");
        }

        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // =============================
        // ADMIN EDIT USER
        // =============================
        [HttpGet]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();

            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, User editedUser)
        {
            if (id != editedUser.UserId) return NotFound();
            if (!ModelState.IsValid) return View(editedUser);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == id);
            if (user == null) return NotFound();

            user.Email = editedUser.Email;
            user.FullName = editedUser.FullName;
            user.PhoneNumber = editedUser.PhoneNumber;
            user.Role = editedUser.Role;

            if (!string.IsNullOrWhiteSpace(editedUser.PasswordHash))
                user.PasswordHash = HashPassword(editedUser.PasswordHash);

            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "User updated successfully!";
            return RedirectToAction(nameof(Index));
        }

        // =============================
        // DELETE USER
        // =============================
        [HttpGet]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();

            var user = await _context.Users.FirstOrDefaultAsync(m => m.UserId == id);
            if (user == null) return NotFound();

            return View(user);
        }

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
                if (user.DisasterReports.Any()) _context.DisasterReports.RemoveRange(user.DisasterReports);
                if (user.Donations.Any()) _context.Donations.RemoveRange(user.Donations);
                if (user.Volunteers.Any()) _context.Volunteers.RemoveRange(user.Volunteers);

                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
            }

            TempData["SuccessMessage"] = "User deleted successfully!";
            return RedirectToAction(nameof(Index));
        }

        // =============================
        // EDIT PROFILE (LOGGED-IN USER)
        // =============================
        [HttpGet]
        public async Task<IActionResult> EditProfile()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
                return RedirectToAction("Login", "Users");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            if (user == null)
                return NotFound();

            return View("Edit", user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(User editedUser)
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
                return RedirectToAction("Login", "Users");

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            if (user == null)
                return NotFound();

            if (!ModelState.IsValid)
                return View("Edit", editedUser);

            bool hasChanges = false;

            if (user.FullName != editedUser.FullName)
            {
                user.FullName = editedUser.FullName;
                hasChanges = true;
            }

            if (user.PhoneNumber != editedUser.PhoneNumber)
            {
                user.PhoneNumber = editedUser.PhoneNumber;
                hasChanges = true;
            }

            if (!string.IsNullOrWhiteSpace(editedUser.PasswordHash))
            {
                user.PasswordHash = HashPassword(editedUser.PasswordHash);
                hasChanges = true;
            }

            if (hasChanges)
            {
                _context.Update(user);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Profile updated successfully!";
            }
            else
            {
                TempData["SuccessMessage"] = "No changes were made.";
            }

            return RedirectToAction("Dashboard", "Home");
        }
    }
}
