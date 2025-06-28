using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWTRefreshTokenInDotNet6.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50)]
        public string? Name { get; set; } 

        public string? Country { get; set; }

        public DateTime? DateOfBirth { get; set; } 

        public string? ProfileImageUrl { get; set; } 

        public string? vrevication { get; set; }

        public string? OtpCode { get; set; }

        public DateTime? CodeExpiryTime { get; set; }

        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}