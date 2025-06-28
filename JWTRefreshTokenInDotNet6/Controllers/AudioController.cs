using Microsoft.AspNetCore.Mvc;

namespace VoiceDetection.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AudioController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;

        public AudioController(IWebHostEnvironment env)
        {
            _env = env;
        }

        //[HttpGet("play")]
        //public IActionResult PlayAudio(string filename)
        //{
        //    if (string.IsNullOrWhiteSpace(filename))
        //        return BadRequest("❌ اسم الملف مطلوب.");

        //    // ✅ فك تشفير اسم الملف من URL
        //    filename = Uri.UnescapeDataString(filename);

        //    var filePath = Path.Combine(_env.WebRootPath, "uploads", filename);

        //    if (!System.IO.File.Exists(filePath))
        //        return NotFound("❌ الملف غير موجود.");

        //    var contentType = "audio/mpeg";
        //    var extension = Path.GetExtension(filename).ToLower();

        //    if (extension == ".wav")
        //        contentType = "audio/wav";

        //    var fileBytes = System.IO.File.ReadAllBytes(filePath);
        //    return File(fileBytes, contentType);
        //}

    }
}
