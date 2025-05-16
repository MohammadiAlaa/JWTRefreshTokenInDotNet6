
using JWTRefreshTokenInDotNet6.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;
using VoiceDetection.Models;
using VoiceDetection.Services;

namespace FinalProject.src.Infrastructure.Services
{
    public class BlacklistService : IBlacklistService
    {
        private readonly ApplicationDbContext _context;

        public BlacklistService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task AddTokenToBlacklistAsync(string token, DateTime expiration)
        {
            var blacklistedToken = new BlacklistedToken
            {
                Token = token,
                ExpirationDate = expiration
            };
            _context.BlacklistedTokens.Add(blacklistedToken);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> IsTokenBlacklistedAsync(string token)
        {
            return await _context.BlacklistedTokens
                .AnyAsync(t => t.Token == token && t.ExpirationDate > DateTime.UtcNow);
        }

        public async Task CleanExpiredTokensAsync()
        {
            var expiredTokens = await _context.BlacklistedTokens
                .Where(t => t.ExpirationDate <= DateTime.UtcNow)
                .ToListAsync();

            if (expiredTokens.Any())
            {
                _context.BlacklistedTokens.RemoveRange(expiredTokens);
                await _context.SaveChangesAsync();
            }
        }
    }
}
