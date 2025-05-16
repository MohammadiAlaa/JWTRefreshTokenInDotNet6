using JWTRefreshTokenInDotNet6.Models;
using JWTRefreshTokenInDotNet6.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using VoiceDetection.Dto;
using VoiceDetection.Services;

namespace JWTRefreshTokenInDotNet6.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly EmailService _emailService;
        private readonly IBlacklistService _blacklistService;


        public AuthController(IAuthService authService, UserManager<ApplicationUser> userManager,IConfiguration configuration,EmailService emailService, IBlacklistService blacklistService)        {
            _authService = authService;
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _blacklistService = blacklistService;
        }

        //[HttpPost("register")]
        //public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        //{
        //    if (!ModelState.IsValid)
        //        return BadRequest(ModelState);

        //    var result = await _authService.RegisterAsync(model);

        //    if (!result.IsAuthenticated)
        //        return BadRequest(result.Message);

        //    SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

        //    return Ok(result);
        //}

        //[HttpPost("token")]
        //public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        //{
        //    var result = await _authService.GetTokenAsync(model);

        //    if (!result.IsAuthenticated)
        //        return BadRequest(result.Message);

        //    if(!string.IsNullOrEmpty(result.RefreshToken))
        //        SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

        //    return Ok(result);
        //}

        [HttpPost("addRole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }

        #region Refresh Token
        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Refresh token is missing.");

            if (await _blacklistService.IsTokenBlacklistedAsync(refreshToken))
                return Unauthorized("This token has been revoked");

            var result = await _authService.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
                return BadRequest(result);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Refresh token is required");

            if (await _blacklistService.IsTokenBlacklistedAsync(refreshToken))
                return Unauthorized("This token has been revoked");

            var result = await _authService.RefreshTokenAsync(refreshToken);
            if (!result.IsAuthenticated)
                return BadRequest(result);

            return Ok(result);
        }
        #endregion

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
        {
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest("Token is required!");

            var result = await _authService.RevokeTokenAsync(token);

            if(!result)
                return BadRequest("Token is invalid!");

            return Ok();
        }

        private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                 HttpOnly = true,
                Expires = expires.ToLocalTime(),
                Secure = true,
                IsEssential = true,
                SameSite = SameSiteMode.None
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }


        ///////////////////////////////////////////////////////////////////
        //[HttpPost("send-otp")]
        //public async Task<IActionResult> SendOtp([FromBody] string email)
        //{
        //    var result = await _authService.SendVerificationCodeAsync(email);
        //    return Ok(result);
        //}

        //[HttpPost("verify-otp")]
        //public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpModel model)
        //{
        //    var isValid = await _authService.VerifyOtpAsync(model.Email, model.Otp);
        //    if (!isValid) return BadRequest("Invalid or expired OTP");
        //    return Ok("OTP verified successfully");
        //}

        [HttpPost("ForgetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgetPassword([FromBody] SendOtpDto email)
        {
            var user = await _userManager.FindByEmailAsync(email.Email);
            if (user == null)
                return BadRequest("User not found.");

            var otp = _emailService.GenerateVerificationCode();

            user.OtpCode = otp;
            user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
            await _userManager.UpdateAsync(user);

            HttpContext.Session.SetString("ResetPasswordUserId", user.Id);
            await _emailService.SendEmailAsync(email.Email, "Verification Code", $"Your OTP code is: {otp}");
            return Ok("OTP sent successfully.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var userId = HttpContext.Session.GetString("ResetPasswordUserId");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest();
            }

            if (model.NewPassword != model.ConfirmNewPassword)
            {
                return BadRequest();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);
            if (!result.Succeeded)
            {
                return BadRequest();
            }

            HttpContext.Session.Remove("ResetPasswordUserId");
            return Ok("Reset Password Sucessfully!");
        }

        [HttpPut("complete-profile")]
        [Authorize]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> CompleteProfile([FromForm] CompleteProfileDto model)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found");

            var result = await _authService.CompleteUserProfileAsync(userId, model);

            if (result != "Succeeded") 
                return BadRequest(result);

            return Ok(new { message = result });
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found");

            var result = await _authService.GetUserProfileAsync(userId);

            if (result == null)
                return NotFound("User not found");

            return Ok(new { message = "Profile fetched successfully", data = result });
        }

        [Authorize]
        [HttpDelete("delete-profile")]
        public async Task<IActionResult> DeleteProfile()
        {
            var userId = _userManager.GetUserId(User); 

            var result = await _authService.DeleteProfileAsync(userId);

            if (!result)
                return NotFound(new { message = "User not found or delete failed." });

            return Ok(new { message = "Profile deleted successfully." });
        }
    }
}
