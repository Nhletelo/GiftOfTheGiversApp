using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GiftOfTheGiversApp.Models
{
    public class DisasterReport
    {
        [Key]
        public int ReportId { get; set; }

        [Required]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; }

        [Required]
        public string Location { get; set; }

        public string Description { get; set; }

        public DateTime ReportDate { get; set; } = DateTime.Now;

        [Required]
        [RegularExpression("New|InProgress|Resolved")]
        public string Status { get; set; }

        [Required]
        [RegularExpression("Low|Medium|High")]
        public string Severity { get; set; }
    }
}

