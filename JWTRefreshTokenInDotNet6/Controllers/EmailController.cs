using JWTRefreshTokenInDotNet6.Models;
using JWTRefreshTokenInDotNet6.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using VoiceDetection.Dto;
using VoiceDetection.Services;
using static System.Net.WebRequestMethods;

namespace JWTRefreshTokenInDotNet6.Controllers  
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly EmailService _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IBlacklistService _blacklistService;

        public EmailController(EmailService emailService, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, IAuthService authService,
            IHttpContextAccessor httpContextAccessor,
            IBlacklistService blacklistService)
        {
            _emailService = emailService;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _authService = authService;
            _httpContextAccessor = httpContextAccessor;
            _blacklistService = blacklistService;
        }

        private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                IsEssential = true,
                Expires = expires.ToLocalTime()
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel request)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest(new { message = "Email and Password are required." });
            }

            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return BadRequest(new { message = "Email is already registered." });
            }
            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                
            };

            var otp = new Random().Next(1000, 9999).ToString();
            user.OtpCode = otp;
            user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
            await _userManager.UpdateAsync(user);

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Registration failed.", errors = result.Errors });
            }
            await _emailService.SendEmailAsync(user.Email, "Verification Code", $"Your Verification code is: {otp}");
            return Ok(new { message = "Registration successful! Please Verifiy code ." });
        }

        [HttpPost("send-verification")]
        public async Task<IActionResult> SendVerificationCode([FromBody] SendOtpDto email)
        {

            if (string.IsNullOrWhiteSpace(email.Email))
            {
                return BadRequest(new { message = "Email cannot be empty." });
            }

            var user = await _userManager.FindByEmailAsync(email.Email);
            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            //await _emailService.SendVerificationCodeAsync(user);
            await _authService.SendVerificationCodeAsync(email);

            return Ok(new { message = "Verification code sent successfully!" });
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyOtpModel request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest(new { message = "Invalid email." });
            }

            if (user.OtpCode != request.Otp || user.CodeExpiryTime < DateTime.UtcNow)
            {
                return BadRequest(new { message = "Invalid or expired verification code." });
            }

            user.EmailConfirmed = true;
            //user.OtpCode = null;
            //user.CodeExpiryTime = null;

            await _userManager.UpdateAsync(user);

            return Ok(new { message = "Email verified successfully! You can now log in." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                return BadRequest(new { message = "Email and Password are required." });

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !user.EmailConfirmed)
                return BadRequest(new { message = "Invalid email or unverified account." });

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                return BadRequest(new { message = "Invalid email or password." });
            
            user.RefreshTokens.RemoveAll(rt => !rt.IsActive && rt.ExpiresOn <= DateTime.UtcNow);

            var refreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
            SetRefreshTokenInCookie(refreshToken.Token, refreshToken.ExpiresOn);

            var token = GenerateJwtToken(user);
            return Ok(new
            {
                message = "Login successful!",
                token,
                refreshToken = refreshToken.Token
            });
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(ClaimTypes.Role, "User"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("uid", user.Id)
            };

            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            byte[] randomNumber = RandomNumberGenerator.GetBytes(32);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddMinutes(30),
                CreatedOn = DateTime.UtcNow
            };
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RevokeToken refreshToken)
        {
            try
            {
                if (string.IsNullOrEmpty(refreshToken.Token))
                    return BadRequest(new { message = "Refresh token not found." });

                var user = await _userManager.Users
                    .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == refreshToken.Token));

                if (user == null)
                    return Unauthorized(new { message = "Invalid token." });

                var token = user.RefreshTokens.SingleOrDefault(t => t.Token == refreshToken.Token);

                if (token == null || !token.IsActive)
                    return BadRequest(new { message = "Token already revoked or expired." });

                token.RevokedOn = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                var expiration = DateTime.UtcNow.AddDays(1);
                await _blacklistService.AddTokenToBlacklistAsync(refreshToken.Token, expiration);

                return Ok(new { message = "Logged out successfully." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }


        public class LoginRequest
        {
            public string Email { get; set; }
            public string Password { get; set; }
        }
        
    }
}
