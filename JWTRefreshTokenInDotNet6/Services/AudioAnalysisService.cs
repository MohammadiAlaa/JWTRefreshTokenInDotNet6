using JWTRefreshTokenInDotNet6.Models;
using Newtonsoft.Json;
using VoiceDetection.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using NAudio.Wave;
using VoiceDetection.Dto;

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

        

        public async Task<AudioAnalysisHistory> AnalyzeOnlyAsync(string userId, IFormFile smallAudio)
        {
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            var cleanedFileName = Path.GetFileNameWithoutExtension(smallAudio.FileName);
            var extension = Path.GetExtension(smallAudio.FileName);
            var safeFileName = $"{Guid.NewGuid()}_{cleanedFileName.Replace(" ", "_")}{extension}";
            var tempSmallPath = Path.Combine(uploadsPath, safeFileName);

            //  حفظ الملف
            using (var stream = new FileStream(tempSmallPath, FileMode.Create, FileAccess.Write))
            {
                await smallAudio.CopyToAsync(stream);
            }

            //  اطبع اسم ومسار الملف بعد الحفظ
            Console.WriteLine($"الملف اتحفظ في: {tempSmallPath}");
            Console.WriteLine($" الرابط اللي هيتخزن في DB: {_configuration["BaseUrl"]}/uploads/{Uri.EscapeDataString(safeFileName)}");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

            var mlApiUrl = _configuration["MLApi:Url"];
            if (string.IsNullOrWhiteSpace(mlApiUrl))
                throw new Exception(" ML API URL is missing from configuration (MLApi:Url)");

            string resultJson;
            using (var fileStream = File.OpenRead(tempSmallPath))
            using (var content = new MultipartFormDataContent
        {
            { new StreamContent(fileStream), "file", safeFileName }
        })
            {
                var response = await _httpClient.PostAsync(mlApiUrl, content);
                resultJson = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                    throw new Exception($" AnalyzeOnlyAsync Failed: {resultJson}");
            }

            dynamic resultData = JsonConvert.DeserializeObject(resultJson);

            //  رابط الملف
            var fileUrl = $"{_configuration["BaseUrl"]}/uploads/{Uri.EscapeDataString(safeFileName)}";

            var history = new AudioAnalysisHistory
            {
                AudioFilePath = fileUrl,
                Result = resultData.prediction,
                Confidence = (float)resultData.confidence,
                UserId = userId,
                CreatedAt = DateTime.UtcNow,
                User = null
            };

            _context.AudioAnalysisHistories.Add(history);
            await _context.SaveChangesAsync();

            return history;
        }
        public async Task<AudioAnalysisHistory> SaveBigFileWithResultAsync(string userId, IFormFile bigAudio, string result, float confidence)
        {
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            var bigFileName = $"{Guid.NewGuid()}_{bigAudio.FileName}";
            var bigFilePath = Path.Combine(uploadsPath, bigFileName);

            using (var stream = new FileStream(bigFilePath, FileMode.Create))
            {
                await bigAudio.CopyToAsync(stream);
            }

            var fileUrl = $"{_configuration["BaseUrl"]}/uploads/{bigFileName}";

            var history = new AudioAnalysisHistory
            {
                AudioFilePath = fileUrl,
                Result = result,
                Confidence = confidence,
                UserId = userId,
                CreatedAt = DateTime.UtcNow
            };

            _context.AudioAnalysisHistories.Add(history);
            await _context.SaveChangesAsync();

            return history;
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
