﻿using JWTRefreshTokenInDotNet6.Models;

namespace JWTRefreshTokenInDotNet6.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
        Task<AuthModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
        Task<string> SendVerificationCodeAsync(string email);
        Task<bool> VerifyOtpAsync(string email, string otp);
        Task<bool> ResetPasswordAsync(ResetPasswordModel model);
    }
}