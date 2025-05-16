using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VoiceDetection.Models;

namespace JWTRefreshTokenInDotNet6.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        { }
        
        public DbSet<AudioAnalysisHistory> AudioAnalysisHistories { get; set; }
        public DbSet<BlacklistedToken> BlacklistedTokens { get; set; }

    }
}