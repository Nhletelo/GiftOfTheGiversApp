using System;
using System.ComponentModel.DataAnnotations;

namespace GiftOfTheGiversApp.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        [RegularExpression("Donor|Volunteer|Admin")]
        public string Role { get; set; } // Donor, Volunteer, Admin

        [Required]
        public string FullName { get; set; }

        public string PhoneNumber { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.Now;

        public ICollection<DisasterReport> DisasterReports { get; set; }
        public ICollection<Donation> Donations { get; set; }
        public ICollection<Volunteer> Volunteers { get; set; }
    }
}

