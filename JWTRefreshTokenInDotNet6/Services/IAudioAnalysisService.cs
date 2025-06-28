using VoiceDetection.Dto;
using VoiceDetection.Models;

namespace VoiceDetection.Services
{
    public interface IAudioAnalysisService
    {
        //Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile smallAudio, IFormFile bigAudio);
        Task<List<AudioAnalysisHistory>> GetUserHistoryAsync(string userId);

        Task<AudioAnalysisHistory> AnalyzeOnlyAsync(string userId, IFormFile smallAudio);
        Task<AudioAnalysisHistory> SaveBigFileWithResultAsync(string userId, IFormFile bigAudio, string result, float confidence);


        Task<bool> DeleteAnalysisAsync(string userId, int analysisId);
        Task<int> DeleteAllHistoryAsync(string userId);


    }
}
