
using JWTRefreshTokenInDotNet6.Models;
using Microsoft.AspNetCore.Identity;
using System.Net.Mail;
using System.Net;

namespace JWTRefreshTokenInDotNet6.Services
{
    public class EmailService 
    {
        
            private readonly string _smtpServer;
            private readonly int _smtpPort;
            private readonly string _smtpUsername;
            private readonly string _smtpPassword;
            private readonly string _fromEmail;
            private readonly UserManager<ApplicationUser> _userManager;

            public EmailService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
            {
                _smtpServer = configuration["EmailSettings:SmtpServer"] ?? throw new ArgumentNullException("SmtpServer is missing");
                _smtpPort = int.TryParse(configuration["EmailSettings:SmtpPort"], out int port) ? port : throw new ArgumentNullException("SmtpPort is missing");
                _smtpUsername = configuration["EmailSettings:SmtpUsername"] ?? throw new ArgumentNullException("SmtpUsername is missing");
                _smtpPassword = configuration["EmailSettings:SmtpPassword"] ?? throw new ArgumentNullException("SmtpPassword is missing");
                _fromEmail = configuration["EmailSettings:FromEmail"] ?? throw new ArgumentNullException("FromEmail is missing");
                _userManager = userManager;
            }
            public string GenerateVerificationCode()
            {
                return new Random().Next(1000, 9999).ToString();
            }
        public async Task SendVerificationCodeAsync(ApplicationUser user)
        {
            if (user == null || string.IsNullOrWhiteSpace(user.Email))
                throw new ArgumentException("Invalid user or email.");

            string verificationCode = GenerateVerificationCode();

            // حفظ الكود ومدة صلاحيته في المستخدم
            user.OtpCode = verificationCode;
            user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
            await _userManager.UpdateAsync(user);

            var client = new SmtpClient(_smtpServer, _smtpPort)
            {
                Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_fromEmail),
                Subject = "Your Verification Code",
                Body = $@"
        <h2>Password Reset Code</h2>
        <p>Your OTP is: <strong>{verificationCode}</strong></p>
        <p>This code is valid for 5 minutes.</p>
        <br>
        <p>Best regards,</p>
        <p>Your Company Team</p>",
                IsBodyHtml = true
            };

            mailMessage.To.Add(user.Email);
            await client.SendMailAsync(mailMessage);
        }
        public async Task<bool> VerifyCodeAsync(string email, string code)
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null || string.IsNullOrWhiteSpace(code))
                    return false;

                if (user.OtpCode == null || user.CodeExpiryTime == null || user.CodeExpiryTime < DateTime.UtcNow)
                    return false;

                if (user.OtpCode != code)
                    return false;
                user.OtpCode = null!;
                user.CodeExpiryTime = null;
                await _userManager.UpdateAsync(user);

                return true;
            }
    }
}
