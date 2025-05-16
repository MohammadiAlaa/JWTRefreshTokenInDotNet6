using JWTRefreshTokenInDotNet6.Models;
using Newtonsoft.Json;
using VoiceDetection.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;

namespace VoiceDetection.Services
{
    public class AudioAnalysisService : IAudioAnalysisService
    {
        private readonly IWebHostEnvironment _env;
        private readonly ApplicationDbContext _context;
        private readonly HttpClient _httpClient;
        private readonly string _mlApiUrl;
        private readonly IConfiguration _configuration;

        public AudioAnalysisService(
            IWebHostEnvironment env,
            ApplicationDbContext context,
            IHttpClientFactory httpClientFactory,
            IOptions<MLApiSettings> mlApiOptions,
            IConfiguration configuration)
        {
            _env = env;
            _context = context;
            _httpClient = httpClientFactory.CreateClient();
            _mlApiUrl = mlApiOptions.Value.Endpoint;
            _configuration = configuration;
        }

        public async Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile file)
        {
            string Url = _configuration["BaseUrl"];
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsPath)) Directory.CreateDirectory(uploadsPath);

            var uniqueFileName = $"{Guid.NewGuid()}_{file.FileName}";
            var filePath = Path.Combine(uploadsPath, uniqueFileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            var form = new MultipartFormDataContent();
            form.Add(new StreamContent(System.IO.File.OpenRead(filePath)), "file", file.FileName);

            var response = await _httpClient.PostAsync(_mlApiUrl, form);
            var resultJson = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                throw new Exception($"API call failed. StatusCode: {response.StatusCode}, Response: {resultJson}");

            dynamic resultData = JsonConvert.DeserializeObject(resultJson);

            var result = new AudioAnalysisHistory
            {
                AudioFilePath = $"{Url}/uploads/{uniqueFileName}",
                Result = resultData.prediction,
                Confidence = (float)resultData.confidence,
                UserId = userId,
                CreatedAt = DateTime.UtcNow
            };

            _context.AudioAnalysisHistories.Add(result);
            await _context.SaveChangesAsync();

            return result;
        }

        public async Task<List<AudioAnalysisHistory>> GetUserHistoryAsync(string userId)
        {
            return await _context.AudioAnalysisHistories
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.CreatedAt)
                .ToListAsync();
        }

        public async Task<bool> DeleteAnalysisAsync(string userId, int analysisId)
        {
            var analysis = await _context.AudioAnalysisHistories
                .FirstOrDefaultAsync(a => a.Id == analysisId && a.UserId == userId);

            if (analysis == null)
                return false;

            var filePath = Path.Combine(_env.WebRootPath, "uploads", Path.GetFileName(analysis.AudioFilePath));
            if (File.Exists(filePath))
                File.Delete(filePath);

            _context.AudioAnalysisHistories.Remove(analysis);
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<int> DeleteAllHistoryAsync(string userId)
        {
            var userHistory = await _context.AudioAnalysisHistories
                .Where(a => a.UserId == userId)
                .ToListAsync();

            if (!userHistory.Any())
                return 0;

            foreach (var item in userHistory)
            {
                var filePath = Path.Combine(_env.WebRootPath, "uploads", Path.GetFileName(item.AudioFilePath));
                if (File.Exists(filePath))
                    File.Delete(filePath);
            }
            _context.AudioAnalysisHistories.RemoveRange(userHistory);
            await _context.SaveChangesAsync();
            return userHistory.Count;
        }
    }

}
