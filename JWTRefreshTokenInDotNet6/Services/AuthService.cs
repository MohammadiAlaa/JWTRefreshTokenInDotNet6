using JWTRefreshTokenInDotNet6.Models;
using JWTRefreshTokenInDotNet6.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using JWTRefreshTokenInDotNet6.Migrations;
using VoiceDetection.Dto;
using Microsoft.AspNetCore.Hosting;

namespace JWTRefreshTokenInDotNet6.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        private readonly EmailService _emailService;
        private readonly Dictionary<string, (string Code, DateTime Expiry)> _otpStore = new();
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, 
            IOptions<JWT> jwt, EmailService emailService, ApplicationDbContext applicationDbContext, 
            IWebHostEnvironment webHostEnvironment, IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
            _emailService = emailService;
            _applicationDbContext = applicationDbContext;
            _webHostEnvironment = webHostEnvironment;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already registered!" };

            if (await _userManager.FindByNameAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already registered!" };

            var user = new ApplicationUser
            {
                UserName= model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;

                foreach (var error in result.Errors)
                    errors += $"{error.Description},";

                return new AuthModel { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");
            var jwtSecurityToken =  GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();
            user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            };
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            var jwtSecurityToken =  GenerateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();
            if(user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = activeRefreshToken.Token;
                authModel.RefreshTokenExpiration = activeRefreshToken.ExpiresOn;
            }
            else
            {
                var refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
                _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = refreshToken.ExpiresOn
                });
            }
            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }

        private JwtSecurityToken GenerateJwtToken(ApplicationUser user)
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

            return token;
        }


        //public async Task<AuthModel> RefreshTokenAsync(string token)
        //{
        //    var authModel = new AuthModel();

        //    var user = await _userManager.Users
        //        .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
        //    if (user == null)
        //    {
        //        authModel.Message = "Invalid token";
        //        return authModel;
        //    }

        //    var refreshToken = user.RefreshTokens.SingleOrDefault(t => t.Token == token);
        //    if (refreshToken == null || !refreshToken.IsActive)
        //    {
        //        authModel.Message = "Token is inactive or revoked";
        //        return authModel;
        //    }
        //    refreshToken.RevokedOn = DateTime.UtcNow;
        //    var newRefreshToken = GenerateRefreshToken();
        //    user.RefreshTokens.Add(newRefreshToken);
        //    user.RefreshTokens.RemoveAll(t => !t.IsActive && t.ExpiresOn <= DateTime.UtcNow);
        //    await _userManager.UpdateAsync(user);
        //    _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", newRefreshToken.Token, new CookieOptions
        //    {
        //        HttpOnly = true,
        //        Secure = true,
        //        SameSite = SameSiteMode.None,
        //        Expires = newRefreshToken.ExpiresOn
        //    });

        //    var jwtToken = GenerateJwtToken(user);
        //    authModel.IsAuthenticated = true;
        //    authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
        //    authModel.Email = user.Email;
        //    authModel.Username = user.UserName;
        //    authModel.Roles = (await _userManager.GetRolesAsync(user)).ToList();
        //    authModel.RefreshToken = newRefreshToken.Token;
        //    authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;

        //    return authModel;
        //}

        public async Task<AuthModel> RefreshTokenAsync(RevokeToken token)
        {
            var authModel = new AuthModel();

            if (string.IsNullOrEmpty(token.Token))
            {
                authModel.Message = "Refresh token is missing";
                return authModel;
            }

            var user = await _userManager.Users
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token.Token));

            if (user == null)
            {
                authModel.Message = "Invalid token";
                return authModel;
            }

            var refreshToken = user.RefreshTokens.SingleOrDefault(t => t.Token == token.Token);
            if (refreshToken == null || !refreshToken.IsActive)
            {
                authModel.Message = "Token is inactive or revoked";
                return authModel;
            }

            refreshToken.RevokedOn = DateTime.UtcNow;
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            user.RefreshTokens.RemoveAll(t => !t.IsActive && t.ExpiresOn <= DateTime.UtcNow);

            await _userManager.UpdateAsync(user);

            var jwtToken = GenerateJwtToken(user);
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.Roles = (await _userManager.GetRolesAsync(user)).ToList();
            authModel.RefreshToken = newRefreshToken.Token;                         
            authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;          

            return authModel;
        }


        public async Task<ApplicationUser> ValidateUserAsync()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null || httpContext.User == null || !httpContext.User.Identity.IsAuthenticated)
            {
                throw new UnauthorizedAccessException("Invalid or expired token.");
            }

            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                throw new UnauthorizedAccessException("User ID not found in token.");
            }

            var userData = await _userManager.Users
                  .FirstOrDefaultAsync(u => u.Id == userId);
            if (userData == null)
            {
                throw new UnauthorizedAccessException("User not found.");
            }

            var token = httpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (string.IsNullOrEmpty(token))
            {
                throw new UnauthorizedAccessException("Token is missing.");
            }

            var isBlacklisted = await _applicationDbContext.BlacklistedTokens.AnyAsync(bt => bt.Token == token);
            if (isBlacklisted)
            {
                throw new UnauthorizedAccessException("Access denied: Token is revoked.");
            }
            return userData;
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
                return false;

            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);

            if (!refreshToken.IsActive)
                return false;

            refreshToken.RevokedOn = DateTime.UtcNow;

            await _userManager.UpdateAsync(user);

            return true;
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
        
        public async Task<string?> SendVerificationCodeAsync(SendOtpDto email)
        {
            var user = await _userManager.FindByEmailAsync(email.Email);

            if (user == null)
                return null;

            var otp = new Random().Next(1000, 9999).ToString();

            user.OtpCode = otp;
            user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(185);

            await _userManager.UpdateAsync(user);

            var emailBody = $"رمز التحقق الخاص بك هو: {otp}. هذا الرمز سينتهي خلال 5 دقائق.";

            var emailSent = await _emailService.SendEmailAsync(email.Email, "رمز التحقق", emailBody);

            return emailSent ? "تم إرسال رمز التحقق وحفظه بنجاح" : null;
        }

        public async Task<bool> VerifyOtpAsync(string email, string otp)
        {
            if (_otpStore.TryGetValue(email, out var storedOtp))
            {
                Console.WriteLine($"Stored OTP: {storedOtp.Code}, Expiry: {storedOtp.Expiry}");

                if (storedOtp.Code == otp && storedOtp.Expiry > DateTime.UtcNow)
                {
                    _otpStore.Remove(email);
                    return true;
                }
                Console.WriteLine("OTP mismatch or expired");
            }
            else
            {
                Console.WriteLine("OTP not found in store");
            }
            return false;
        }
        public async Task<bool> VerifyOtpForResetPassAsync(ResetPasswordModel otp)
        {
            
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == otp.Email);
            if (user == null || user.OtpCode != otp.Otp || user.CodeExpiryTime < DateTime.UtcNow)
                return false;

            //user.PhoneNumberConfirmed = true;
            //user.EmailConfirmed = true;
            //user.OtpCode = null;
            //user.CodeExpiryTime = null;
            //await _userManager.UpdateAsync(user);

            return true;
        }

        //public async Task<string?> SendVerificationCodeAsync(SendOtpDto email)
        //{
        //    var user = await _userManager.FindByEmailAsync(email.Email);
        //    if (user == null)
        //        return null;
        //
        //    var otp = new Random().Next(1000, 9999).ToString();
        //    user.OtpCode = otp;
        //    user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
        //    await _userManager.UpdateAsync(user);
        //
        //    var emailSent = await _emailService.SendEmailAsync(email.Email, "Verification Code", $"Your OTP code is: {otp}");
        //    return emailSent ? "OTP sent and saved successfully" : null;
        //}
        //
        //public async Task<bool> VerifyOtpAsync(string email, string otp)
        //{
        //    if (_otpStore.TryGetValue(email, out var storedOtp) && storedOtp.Code == otp && storedOtp.Expiry > DateTime.UtcNow)
        //    {
        //        _otpStore.Remove(email);
        //        return true;
        //    }
        //    return false;
        //}

        public async Task<string> ResetPasswordAsync(ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return "User not found";

            if (!await VerifyOtpForResetPassAsync(model))
                return "Invalid or expired OTP";

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, model.NewPassword);

            if (!result.Succeeded)
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                return $"Password reset failed: {errors}";
            }

            return "Success";
        }


        public async Task<string> CompleteUserProfileAsync(string userId, CompleteProfileDto model)
        {
            var Url = _configuration["BaseUrl"];

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return "User not found";

            if (!string.IsNullOrEmpty(model.Name))
                user.Name = model.Name;

            if (!string.IsNullOrEmpty(model.PhoneNumber))
                user.PhoneNumber = model.PhoneNumber;

            if (!string.IsNullOrEmpty(model.Country))
                user.Country = model.Country;

            if (model.DateOfBirth != default)
                user.DateOfBirth = model.DateOfBirth;

            if (model.ProfileImage != null && model.ProfileImage.Length > 0)
            {
                try
                {
                    string webRootPath = _webHostEnvironment?.WebRootPath
                                          ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");

                    string uploadsFolder = Path.Combine(webRootPath, "uploads");
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }

                    string safeFileName = Path.GetFileName(model.ProfileImage.FileName);
                    string uniqueFileName = $"{Guid.NewGuid()}_{safeFileName}";
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.ProfileImage.CopyToAsync(fileStream);
                    }

                    user.ProfileImageUrl = $"{Url}/uploads/{uniqueFileName}";
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error saving profile image: {ex.Message}");
                    return ex.Message;
                }
            }
            
            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded ? "Succeeded" : "Failed to update profile.";
        }


        public async Task<CompleteProfileDto> GetUserProfileAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return null;

            CompleteProfileDto profileDto = new CompleteProfileDto();

            profileDto.Name = string.IsNullOrEmpty(user.Name) ? "Your Name" : user.Name;

            profileDto.PhoneNumber = string.IsNullOrEmpty(user.PhoneNumber) ? "0000000000" : user.PhoneNumber;
            profileDto.Country = string.IsNullOrEmpty(user.Country) ? "Egypt" : user.Country;
            profileDto.Email = string.IsNullOrEmpty(user.Email) ? "example@gmail.com" : user.Email;

            profileDto.DateOfBirth = user.DateOfBirth?.Date ?? new DateTime(2001, 1, 1);  
            profileDto.ProfileImageUrl = string.IsNullOrEmpty(user.ProfileImageUrl)
                                ? $"{_configuration["BaseUrl"]}/uploads/Default_pfp.jpg"
                                : user.ProfileImageUrl;
            return profileDto;
        }
        public async Task<bool> DeleteProfileAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            var audioRecords = _applicationDbContext.AudioAnalysisHistories.Where(h => h.UserId == userId);
            _applicationDbContext.AudioAnalysisHistories.RemoveRange(audioRecords);

            await _applicationDbContext.SaveChangesAsync();
            var result = await _userManager.DeleteAsync(user);

            return result.Succeeded;
        }
    }
}