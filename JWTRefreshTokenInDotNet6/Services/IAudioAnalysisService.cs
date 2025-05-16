using VoiceDetection.Models;

namespace VoiceDetection.Services
{
    public interface IAudioAnalysisService
    {
        Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile file);
        Task<List<AudioAnalysisHistory>> GetUserHistoryAsync(string userId);



        Task<bool> DeleteAnalysisAsync(string userId, int analysisId);
        Task<int> DeleteAllHistoryAsync(string userId);


    }
}
