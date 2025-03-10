using JWTRefreshTokenInDotNet6.Models;
using JWTRefreshTokenInDotNet6.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

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

        public AuthController(IAuthService authService, UserManager<ApplicationUser> userManager,IConfiguration configuration,EmailService emailService)
        {
            _authService = authService;
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
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

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var result = await _authService.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
                return BadRequest(result);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);
        }

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
        public async Task<IActionResult> ForgetPassword([FromBody] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return BadRequest("User not found.");

            // توليد OTP
            var otp = _emailService.GenerateVerificationCode();

            // حفظ OTP والمُهلة الزمنية للمستخدم
            user.OtpCode = otp;
            user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
            await _userManager.UpdateAsync(user);

            // إرسال OTP عبر البريد الإلكتروني
            await _emailService.SendVerificationCodeAsync(user);

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

            // Clear the session after successful password reset
            HttpContext.Session.Remove("ResetPasswordUserId");

            return Ok();
        }

    }
}
