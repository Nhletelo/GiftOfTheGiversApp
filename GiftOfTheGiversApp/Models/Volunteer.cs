using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GiftOfTheGiversApp.Models
{
    public class Volunteer
    {
        [Key]
        public int VolunteerId { get; set; }

        [Required]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; }

        public string Availability { get; set; }

        public string Skills { get; set; }

        public int? TaskId { get; set; }

        [ForeignKey("TaskId")]
        public TaskItem Task { get; set; }

        [RegularExpression("Assigned|Completed")]
        public string TaskStatus { get; set; }
    }
}
