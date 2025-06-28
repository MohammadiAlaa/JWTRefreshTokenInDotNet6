using JWTRefreshTokenInDotNet6.Models;
using VoiceDetection.Dto;

namespace JWTRefreshTokenInDotNet6.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
        // Task<AuthModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
        //Task<string> SendVerificationCodeAsync(string email);
        Task<string> SendVerificationCodeAsync(SendOtpDto email);
        Task<bool> VerifyOtpAsync(string email, string otp);
        Task<string> ResetPasswordAsync(ResetPasswordModel model);

        Task<bool> VerifyOtpForResetPassAsync(ResetPasswordModel otp);
        ////////////////////////////////////////////////////////////////
        Task<string> CompleteUserProfileAsync(string userId, CompleteProfileDto model);
        Task<CompleteProfileDto> GetUserProfileAsync(string userId);
        Task<AuthModel> RefreshTokenAsync(RevokeToken token);

        Task<ApplicationUser> ValidateUserAsync();

        Task<bool> DeleteProfileAsync(string userId);


    }
}