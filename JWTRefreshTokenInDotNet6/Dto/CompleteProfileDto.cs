using System.ComponentModel.DataAnnotations;

namespace VoiceDetection.Dto
{
    public class CompleteProfileDto
    {
        
        [MaxLength(50)]
        public string? Name { get; set; }

        public string? PhoneNumber { get; set; }

        public string? Country { get; set; }
        public string? Email { get; set; }

        public DateTime? DateOfBirth { get; set; }

        public IFormFile? ProfileImage { get; set; } 
        public string? ProfileImageUrl { get; set; }  

    }
}
