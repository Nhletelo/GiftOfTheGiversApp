using Microsoft.EntityFrameworkCore;
using GiftOfTheGiversApp.Models;

namespace GiftOfTheGiversApp.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<DisasterReport> DisasterReports { get; set; }
        public DbSet<Donation> Donations { get; set; }
        public DbSet<Volunteer> Volunteers { get; set; }
        public DbSet<TaskItem> Tasks { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Cascade delete for DisasterReports
            modelBuilder.Entity<DisasterReport>()
                .HasOne(d => d.User)
                .WithMany(u => u.DisasterReports)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Cascade delete for Donations
            modelBuilder.Entity<Donation>()
                .HasOne(d => d.User)
                .WithMany(u => u.Donations)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Cascade delete for Volunteers
            modelBuilder.Entity<Volunteer>()
                .HasOne(v => v.User)
                .WithMany(u => u.Volunteers)
                .HasForeignKey(v => v.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
