using Microsoft.AspNetCore.Mvc;

namespace VoiceDetection.Controllers
{
    public class FilesController : Controller
    {
        private readonly IWebHostEnvironment _env;

        public FilesController(IWebHostEnvironment env)
        {
            _env = env;
        }

        //[HttpGet("{fileName}")]
        //public IActionResult GetFile(string fileName)
        //{
        //    var filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);

        //    if (!System.IO.File.Exists(filePath))
        //        return NotFound("❌ الملف غير موجود.");

        //    var contentType = "application/octet-stream";
        //    return PhysicalFile(filePath, contentType);
        //}
    }
}
