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

        //public async Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile smallAudio, IFormFile bigAudio)
        //{
        //    string Url = _configuration["BaseUrl"];
        //    _httpClient.DefaultRequestHeaders.Clear();
        //    _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //    if (!Directory.Exists(uploadsPath))
        //        Directory.CreateDirectory(uploadsPath);

        //    // 🔹 حفظ الملف الكبير فقط
        //    var bigFileName = $"{Guid.NewGuid()}_{bigAudio.FileName}";
        //    var bigFilePath = Path.Combine(uploadsPath, bigFileName);
        //    using (var stream = new FileStream(bigFilePath, FileMode.Create))
        //    {
        //        await bigAudio.CopyToAsync(stream);
        //    }

        //    // 🔹 حفظ الملف الصغير مؤقتًا ثم تقطيعه
        //    var tempSmallFileName = $"{Guid.NewGuid()}_{smallAudio.FileName}";
        //    var tempSmallPath = Path.Combine(uploadsPath, tempSmallFileName);
        //    using (var stream = new FileStream(tempSmallPath, FileMode.Create))
        //    {
        //        await smallAudio.CopyToAsync(stream);
        //    }

        //    // 🔹 تقطيع أول 5 ثواني من الملف الصغير
        //    var trimmedFileName = $"{Guid.NewGuid()}_trimmed.wav";
        //    var trimmedPath = Path.Combine(uploadsPath, trimmedFileName);

        //    using (var reader = new AudioFileReader(tempSmallPath))
        //    {
        //        var outFormat = new WaveFormat(16000, 1); // Mono, 16KHz
        //        using (var resampler = new MediaFoundationResampler(reader, outFormat))
        //        {
        //            resampler.ResamplerQuality = 60;
        //            int secondsToTake = 5;
        //            int bytesPerSecond = outFormat.AverageBytesPerSecond;
        //            int bytesToRead = bytesPerSecond * secondsToTake;

        //            byte[] buffer = new byte[bytesToRead];
        //            int read = resampler.Read(buffer, 0, bytesToRead);

        //            using (var writer = new WaveFileWriter(trimmedPath, outFormat))
        //            {
        //                writer.Write(buffer, 0, read);
        //            }
        //        }
        //    }

        //    // 🔹 إرسال الملف المقصوص فقط لـ ML API
        //    var form = new MultipartFormDataContent();
        //    form.Add(new StreamContent(System.IO.File.OpenRead(trimmedPath)), "file", trimmedFileName);

        //    var response = await _httpClient.PostAsync(_mlApiUrl, form);
        //    var resultJson = await response.Content.ReadAsStringAsync();

        //    if (!response.IsSuccessStatusCode)
        //        throw new Exception($"API call failed. StatusCode: {response.StatusCode}, Response: {resultJson}");

        //    dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //    // 🔹 حفظ النتيجة في الداتابيز وربطها بالملف الكبير
        //    var result = new AudioAnalysisHistory
        //    {
        //        AudioFilePath = $"{Url}/uploads/{bigFileName}", // 🔁 نربط النتيجة بالملف الكبير
        //        Result = resultData.prediction,
        //        Confidence = (float)resultData.confidence,
        //        UserId = userId,
        //        CreatedAt = DateTime.UtcNow
        //    };

        //    _context.AudioAnalysisHistories.Add(result);
        //    await _context.SaveChangesAsync();

        //    // حذف الملفات المؤقتة
        //    File.Delete(tempSmallPath);
        //    File.Delete(trimmedPath);

        //    return result;
        //}


        //public async Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile file)
        //{
        //    string Url = _configuration["BaseUrl"];
        //    _httpClient.DefaultRequestHeaders.Clear();
        //    _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //    if (!Directory.Exists(uploadsPath)) Directory.CreateDirectory(uploadsPath);
        //    // حفظ الملف الأصلي
        //    var originalFileName = $"{Guid.NewGuid()}_{file.FileName}";
        //    var originalPath = Path.Combine(uploadsPath, originalFileName);

        //    using (var stream = new FileStream(originalPath, FileMode.Create))
        //    {
        //        await file.CopyToAsync(stream);
        //    }
        //    // تقطيع أول 5 ثواني
        //    var trimmedFileName = $"{Guid.NewGuid()}_trimmed.wav";
        //    var trimmedPath = Path.Combine(uploadsPath, trimmedFileName);

        //    using (var reader = new AudioFileReader(originalPath))
        //    {
        //        var outFormat = new WaveFormat(1600000, 1); // Mono, 16KHz
        //        using (var resampler = new MediaFoundationResampler(reader, outFormat))
        //        {
        //            resampler.ResamplerQuality = 60;
        //            int secondsToTake = 5;
        //            int bytesPerSecond = outFormat.AverageBytesPerSecond;
        //            int bytesToRead = bytesPerSecond * secondsToTake;

        //            byte[] buffer = new byte[bytesToRead];
        //            int read = resampler.Read(buffer, 0, bytesToRead);

        //            using (var writer = new WaveFileWriter(trimmedPath, outFormat))
        //            {
        //                writer.Write(buffer, 0, read);
        //            }
        //        }
        //    }
        //    // إرسال الملف المقصوص فقط لـ ML API
        //    var form = new MultipartFormDataContent();
        //    form.Add(new StreamContent(System.IO.File.OpenRead(trimmedPath)), "file", trimmedFileName);

        //    var response = await _httpClient.PostAsync(_mlApiUrl, form);
        //    var resultJson = await response.Content.ReadAsStringAsync();

        //    if (!response.IsSuccessStatusCode)
        //        throw new Exception($"API call failed. StatusCode: {response.StatusCode}, Response: {"الملف كبير جدًا، يجب ألا يتجاوز 180 كيلوبايت."}");

        //    dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //    var result = new AudioAnalysisHistory
        //    {
        //        AudioFilePath = $"{Url}/uploads/{originalFileName}", // رابط الملف الأصلي
        //        Result = resultData.prediction,
        //        Confidence = (float)resultData.confidence,
        //        UserId = userId,
        //        CreatedAt = DateTime.UtcNow
        //    };
        //    _context.AudioAnalysisHistories.Add(result);
        //    await _context.SaveChangesAsync();

        //    return result;
        //}

        #region  شغال لحد 4 ميجا بس مش بيخزن ولا اي حاجة خالص  
        //public async Task<AnalysisResultDto> AnalyzeOnlyAsync(string userId, IFormFile smallAudio)
        //{
        //    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //    if (!Directory.Exists(uploadsPath))
        //        Directory.CreateDirectory(uploadsPath);

        //    var tempSmallFileName = $"{Guid.NewGuid()}_{smallAudio.FileName}";
        //    var tempSmallPath = Path.Combine(uploadsPath, tempSmallFileName);

        //    await using (var stream = new FileStream(tempSmallPath, FileMode.Create))
        //    {
        //        await smallAudio.CopyToAsync(stream);
        //    }

        //    _httpClient.DefaultRequestHeaders.Clear();
        //    _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //    var mlApiUrl = _configuration["MLApi:Url"];
        //    if (string.IsNullOrWhiteSpace(mlApiUrl))
        //        throw new Exception("❌ ML API URL is missing from configuration (MLApi:Url)");

        //    string resultJson;

        //    await using (var fileStream = File.OpenRead(tempSmallPath))
        //    using (var content = new MultipartFormDataContent
        //    {
        //        { new StreamContent(fileStream), "file", tempSmallFileName }
        //    })
        //    {
        //        var response = await _httpClient.PostAsync(mlApiUrl, content);
        //        resultJson = await response.Content.ReadAsStringAsync();

        //        if (!response.IsSuccessStatusCode)
        //            throw new Exception($"🔥 AnalyzeOnlyAsync Failed: {resultJson}");
        //    }

        //    // ✅ بعد ما الـ stream اتقفل
        //    if (File.Exists(tempSmallPath))
        //        File.Delete(tempSmallPath);

        //    dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //    return new AnalysisResultDto
        //    {
        //        Result = resultData.prediction,
        //        Confidence = (float)resultData.confidence
        //    };
        //}
        #endregion


        // اللي شغال ويحذف من uploads
        //    public async Task<AudioAnalysisHistory> AnalyzeOnlyAsync(string userId, IFormFile smallAudio)
        //    {
        //        var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //        if (!Directory.Exists(uploadsPath))
        //            Directory.CreateDirectory(uploadsPath);

        //        var tempSmallFileName = $"{Guid.NewGuid()}_{smallAudio.FileName}";
        //        var tempSmallPath = Path.Combine(uploadsPath, tempSmallFileName);

        //        await using (var stream = new FileStream(tempSmallPath, FileMode.Create))
        //        {
        //            await smallAudio.CopyToAsync(stream);
        //        }

        //        _httpClient.DefaultRequestHeaders.Clear();
        //        _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //        var mlApiUrl = _configuration["MLApi:Url"];
        //        if (string.IsNullOrWhiteSpace(mlApiUrl))
        //            throw new Exception("❌ ML API URL is missing from configuration (MLApi:Url)");

        //        string resultJson;

        //        await using (var fileStream = File.OpenRead(tempSmallPath))
        //        using (var content = new MultipartFormDataContent
        //{
        //    { new StreamContent(fileStream), "file", tempSmallFileName }
        //})
        //        {
        //            var response = await _httpClient.PostAsync(mlApiUrl, content);
        //            resultJson = await response.Content.ReadAsStringAsync();

        //            if (!response.IsSuccessStatusCode)
        //                throw new Exception($"🔥 AnalyzeOnlyAsync Failed: {resultJson}");
        //        }

        //        if (File.Exists(tempSmallPath))
        //            File.Delete(tempSmallPath);

        //        dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //        // ✅ نحفظ النتيجة زي ما بتطلب
        //        var encodedFileName = Uri.EscapeDataString(tempSmallFileName);
        //        var fileUrl = $"{_configuration["BaseUrl"]}/api/files/{encodedFileName}";

        //        var history = new AudioAnalysisHistory
        //        {
        //            AudioFilePath = $"{_configuration["BaseUrl"]}/api/files/{Uri.EscapeDataString(tempSmallFileName)}",
        //            Result = resultData.prediction,
        //            Confidence = (float)resultData.confidence,
        //            UserId = userId,
        //            CreatedAt = DateTime.UtcNow,
        //            User = null
        //        };

        //        _context.AudioAnalysisHistories.Add(history);
        //        await _context.SaveChangesAsync();

        //        return history;
        //    }



        public async Task<AudioAnalysisHistory> AnalyzeOnlyAsync(string userId, IFormFile smallAudio)
        {
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            var cleanedFileName = Path.GetFileNameWithoutExtension(smallAudio.FileName);
            var extension = Path.GetExtension(smallAudio.FileName);
            var safeFileName = $"{Guid.NewGuid()}_{cleanedFileName.Replace(" ", "_")}{extension}";
            var tempSmallPath = Path.Combine(uploadsPath, safeFileName);

            // ✅ حفظ الملف
            using (var stream = new FileStream(tempSmallPath, FileMode.Create, FileAccess.Write))
            {
                await smallAudio.CopyToAsync(stream);
            }

            // ✨ اطبع اسم ومسار الملف بعد الحفظ
            Console.WriteLine($"📁 الملف اتحفظ في: {tempSmallPath}");
            Console.WriteLine($"🌐 الرابط اللي هيتخزن في الـ DB: {_configuration["BaseUrl"]}/uploads/{Uri.EscapeDataString(safeFileName)}");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

            var mlApiUrl = _configuration["MLApi:Url"];
            if (string.IsNullOrWhiteSpace(mlApiUrl))
                throw new Exception("❌ ML API URL is missing from configuration (MLApi:Url)");

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
                    throw new Exception($"🔥 AnalyzeOnlyAsync Failed: {resultJson}");
            }

            dynamic resultData = JsonConvert.DeserializeObject(resultJson);

            // ✅ رابط الملف
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

        //    public async Task<AudioAnalysisHistory> AnalyzeOnlyAsync(string userId, IFormFile smallAudio)
        //    {
        //        var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //        if (!Directory.Exists(uploadsPath))
        //            Directory.CreateDirectory(uploadsPath);

        //        var cleanedFileName = Path.GetFileNameWithoutExtension(smallAudio.FileName);
        //        var extension = Path.GetExtension(smallAudio.FileName);
        //        var safeFileName = $"{Guid.NewGuid()}_{cleanedFileName.Replace(" ", "_")}{extension}";
        //        var tempSmallPath = Path.Combine(uploadsPath, safeFileName);

        //        // ✅ حفظ الملف
        //        using (var stream = new FileStream(tempSmallPath, FileMode.Create, FileAccess.Write))
        //        {
        //            await smallAudio.CopyToAsync(stream);
        //        }

        //        Console.WriteLine($"📁 الملف اتحفظ في: {tempSmallPath}");

        //        _httpClient.DefaultRequestHeaders.Clear();
        //        _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //        var mlApiUrl = _configuration["MLApi:Url"];
        //        if (string.IsNullOrWhiteSpace(mlApiUrl))
        //            throw new Exception("❌ ML API URL is missing from configuration (MLApi:Url)");

        //        string resultJson;
        //        using (var fileStream = File.OpenRead(tempSmallPath))
        //        using (var content = new MultipartFormDataContent
        //{
        //    { new StreamContent(fileStream), "file", safeFileName }
        //})
        //        {
        //            var response = await _httpClient.PostAsync(mlApiUrl, content);
        //            resultJson = await response.Content.ReadAsStringAsync();

        //            if (!response.IsSuccessStatusCode)
        //                throw new Exception($"🔥 AnalyzeOnlyAsync Failed: {resultJson}");
        //        }

        //        dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //        // ✅ الرابط هيكون من خلال API play
        //        var apiBase = _configuration["BaseUrl"]?.TrimEnd('/');
        //        var apiPlayUrl = $"{apiBase}/api/audio/play?filename={Uri.EscapeDataString(safeFileName)}";

        //        var history = new AudioAnalysisHistory
        //        {
        //            AudioFilePath = apiPlayUrl, // 💡 رابط التشغيل من الكنترولر
        //            Result = resultData.prediction,
        //            Confidence = (float)resultData.confidence,
        //            UserId = userId,
        //            CreatedAt = DateTime.UtcNow,
        //            User = null
        //        };

        //        _context.AudioAnalysisHistories.Add(history);
        //        await _context.SaveChangesAsync();

        //        return history;
        //    }


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

        #region القديم
        //public async Task<AudioAnalysisHistory> AnalyzeAsync(string userId, IFormFile file)
        //{
        //    string Url = _configuration["BaseUrl"];
        //    _httpClient.DefaultRequestHeaders.Clear();
        //    _httpClient.DefaultRequestHeaders.Add("X-API-Key", "test_key");

        //    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
        //    if (!Directory.Exists(uploadsPath)) Directory.CreateDirectory(uploadsPath);

        //    var uniqueFileName = $"{Guid.NewGuid()}_{file.FileName}";
        //    var filePath = Path.Combine(uploadsPath, uniqueFileName);

        //    using (var stream = new FileStream(filePath, FileMode.Create))
        //    {
        //        await file.CopyToAsync(stream);
        //    }

        //    var form = new MultipartFormDataContent();
        //    form.Add(new StreamContent(System.IO.File.OpenRead(filePath)), "file", file.FileName);

        //    var response = await _httpClient.PostAsync(_mlApiUrl, form);
        //    var resultJson = await response.Content.ReadAsStringAsync();

        //    if (!response.IsSuccessStatusCode)
        //        throw new Exception($"API call failed. StatusCode: {response.StatusCode}, Response: {resultJson}");

        //    dynamic resultData = JsonConvert.DeserializeObject(resultJson);

        //    var result = new AudioAnalysisHistory
        //    {
        //        AudioFilePath = $"{Url}/uploads/{uniqueFileName}",
        //        Result = resultData.prediction,
        //        Confidence = (float)resultData.confidence,
        //        UserId = userId,
        //        CreatedAt = DateTime.UtcNow
        //    };

        //    _context.AudioAnalysisHistories.Add(result);
        //    await _context.SaveChangesAsync();

        //    return result;
        //} 
        #endregion

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
