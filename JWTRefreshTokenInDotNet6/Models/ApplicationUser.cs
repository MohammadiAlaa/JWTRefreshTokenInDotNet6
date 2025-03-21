﻿using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWTRefreshTokenInDotNet6.Models
{
    public class ApplicationUser : IdentityUser
    {
        //[MaxLength(50)]
        //public string FirstName { get; set; }

        //[MaxLength(50)]
        //public string LastName { get; set; }

        public string? vrevication { get; set; }

        public string? OtpCode { get; set; }

        public DateTime? CodeExpiryTime { get; set; }

        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}