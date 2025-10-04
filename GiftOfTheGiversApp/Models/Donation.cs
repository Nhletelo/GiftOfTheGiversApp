using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace GiftOfTheGiversApp.Models
{
    public class Donation
    {
        [Key]
        public int DonationId { get; set; }

        [Required]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; }

        [Required]
        [RegularExpression("Food|Clothing|Medical")]
        public string DonationType { get; set; }

        [Required]
        [Range(1, int.MaxValue)]
        public int Quantity { get; set; }

        public DateTime DonationDate { get; set; } = DateTime.Now;

        [Required]
        [RegularExpression("Pending|Delivered")]
        public string Status { get; set; }

        public string DistributionNotes { get; set; }
    }
}
