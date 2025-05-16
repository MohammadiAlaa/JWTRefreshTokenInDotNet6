using JWTRefreshTokenInDotNet6.Models;
using JWTRefreshTokenInDotNet6.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VoiceDetection.Dto;
using VoiceDetection.Services;

namespace VoiceDetection.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AudioAnalysisController : ControllerBase
    {
        private readonly IAudioAnalysisService _audioService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuthService _authService;
        private readonly IBlacklistService _BlacklistService;

        public AudioAnalysisController(IAudioAnalysisService audioService, UserManager<ApplicationUser> userManager, IBlacklistService BlacklistService, IAuthService authService)
        {
            _audioService = audioService;
            _userManager = userManager;
            _BlacklistService = BlacklistService;
            _authService = authService;
        }
        [RequestSizeLimit(104857600)]
        [Authorize]
        [HttpPost("analyze")]
        public async Task<IActionResult> Analyze([FromForm] AnalyzeAudioDto dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _audioService.AnalyzeAsync(userId, dto.AudioFile);
            return Ok(result);
        }

        [Authorize]
        [HttpGet("history")]
        public async Task<IActionResult> GetHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var history = await _audioService.GetUserHistoryAsync(userId);
            return Ok(history);
        }

        [Authorize]
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteAnalysis(int id)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var deleted = await _audioService.DeleteAnalysisAsync(userId, id);

            if (!deleted)
                return NotFound("Analysis not found or access denied.");

            return Ok("Analysis deleted successfully.");
        }

        [Authorize]
        [HttpDelete("clear-history")]
        public async Task<IActionResult> ClearHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var deletedCount = await _audioService.DeleteAllHistoryAsync(userId);

            return Ok(new { message = $"Deleted {deletedCount} item(s) from history." });
        }
    }

}
