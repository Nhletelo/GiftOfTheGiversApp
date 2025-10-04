using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using GiftOfTheGiversApp.Data;
using GiftOfTheGiversApp.Models;


namespace GiftOfTheGiversApp.Controllers
{
    public class DisasterReportsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public DisasterReportsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: DisasterReports
        public async Task<IActionResult> Index()
        {
            var applicationDbContext = _context.DisasterReports.Include(d => d.User);
            return View(await applicationDbContext.ToListAsync());
        }

        // GET: DisasterReports/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var disasterReport = await _context.DisasterReports
                .Include(d => d.User)
                .FirstOrDefaultAsync(m => m.ReportId == id);
            if (disasterReport == null)
            {
                return NotFound();
            }

            return View(disasterReport);
        }

        // GET: DisasterReports/Create
        public IActionResult Create()
        {
            ViewData["UserId"] = new SelectList(_context.Users, "UserId", "Email");
            Console.WriteLine($"User count for dropdown: {_context.Users.Count()}");
            return View();
        }

        // POST: DisasterReports/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ReportId,UserId,Location,Description,ReportDate,Status,Severity")] DisasterReport disasterReport)
        {
            GiftOfTheGiversApp.Models.User user = _context.Users.FirstOrDefault(u => u.UserId == disasterReport.UserId);
            disasterReport.User = user;

            // Default ReportDate if not set
            if (disasterReport.ReportDate == default)
                disasterReport.ReportDate = DateTime.Now;

            _context.Add(disasterReport);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));

        }






        // GET: DisasterReports/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var disasterReport = await _context.DisasterReports.FindAsync(id);
            if (disasterReport == null)
            {
                return NotFound();
            }
            ViewData["UserId"] = new SelectList(_context.Users, "UserId", "Email", disasterReport.UserId);
            return View(disasterReport);
        }

        // POST: DisasterReports/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ReportId,UserId,Location,Description,ReportDate,Status,Severity")] DisasterReport disasterReport)
        {
            if (id != disasterReport.ReportId)
            {
                return NotFound();
            }


            try
            {
                _context.Update(disasterReport);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!DisasterReportExists(disasterReport.ReportId))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            return RedirectToAction(nameof(Index));
        }



        // GET: DisasterReports/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var disasterReport = await _context.DisasterReports
                .Include(d => d.User)
                .FirstOrDefaultAsync(m => m.ReportId == id);
            if (disasterReport == null)
            {
                return NotFound();
            }

            return View(disasterReport);
        }

        // POST: DisasterReports/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var disasterReport = await _context.DisasterReports.FindAsync(id);
            if (disasterReport != null)
            {
                _context.DisasterReports.Remove(disasterReport);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool DisasterReportExists(int id)
        {
            return _context.DisasterReports.Any(e => e.ReportId == id);
        }
    }
}
