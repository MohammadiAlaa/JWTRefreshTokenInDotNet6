using JWTRefreshTokenInDotNet6.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace VoiceDetection.Models
{
    public class AudioAnalysisHistory
    {
        public int Id { get; set; }

        [Required]
        public string AudioFilePath { get; set; } // رابط تحميل الملف

        [Required]
        public string Result { get; set; } // Real / Fake

        [Required]
        public float Confidence { get; set; } // نسبة التأكد

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Required]
        public string UserId { get; set; } 

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }
    }
}
