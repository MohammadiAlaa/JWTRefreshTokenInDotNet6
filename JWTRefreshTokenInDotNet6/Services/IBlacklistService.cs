namespace VoiceDetection.Services
{
    public interface IBlacklistService
    {
        Task AddTokenToBlacklistAsync(string token, DateTime expiration);
        Task<bool> IsTokenBlacklistedAsync(string token);
        /////////////////////////////////////
        Task CleanExpiredTokensAsync();


    }
}
