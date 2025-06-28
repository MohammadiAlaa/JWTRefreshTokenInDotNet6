
using JWTRefreshTokenInDotNet6.Models;
using Microsoft.AspNetCore.Identity;
using System.Net.Mail;
using System.Net;
using MimeKit;
using MailKit.Security;
using MailKit.Net.Smtp;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace JWTRefreshTokenInDotNet6.Services
{
    public class EmailService 
    {
        
            private readonly string _emailFrom;
            private readonly string _emailPassword;




            private readonly string _smtpServer;
            private readonly int _smtpPort;
            //private readonly string _smtpUsername;
            //private readonly string _smtpPassword;
            //private readonly string _fromEmail;
            private readonly UserManager<ApplicationUser> _userManager;

        //public EmailService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        //{
        //    _smtpServer = configuration["EmailSettings:SmtpServer"] ?? throw new ArgumentNullException("SmtpServer is missing");
        //    _smtpPort = int.TryParse(configuration["EmailSettings:SmtpPort"], out int port) ? port : throw new ArgumentNullException("SmtpPort is missing");
        //    _smtpUsername = configuration["EmailSettings:SmtpUsername"] ?? throw new ArgumentNullException("SmtpUsername is missing");
        //    _smtpPassword = configuration["EmailSettings:SmtpPassword"] ?? throw new ArgumentNullException("SmtpPassword is missing");
        //    _fromEmail = configuration["EmailSettings:FromEmail"] ?? throw new ArgumentNullException("FromEmail is missing");
        //    _userManager = userManager;
        //}
        public EmailService(IConfiguration configuration)
        {
            _smtpServer = configuration["EmailSettings:SmtpServer"];
            _smtpPort = int.Parse(configuration["EmailSettings:SmtpPort"]);
            _emailFrom = configuration["EmailSettings:EmailFrom"];
            _emailPassword = configuration["EmailSettings:EmailPassword"];
        }

        public string GenerateVerificationCode()
            {
                return new Random().Next(1000, 9999).ToString();
            }

        //public async Task SendVerificationCodeAsync(ApplicationUser user)
        //{
        //    if (user == null || string.IsNullOrWhiteSpace(user.Email))
        //        throw new ArgumentException("Invalid user or email.");

        //    string verificationCode = GenerateVerificationCode();

        //    // حفظ الكود ومدة صلاحيته في المستخدم
        //    user.OtpCode = verificationCode;
        //    user.CodeExpiryTime = DateTime.UtcNow.AddMinutes(5);
        //    await _userManager.UpdateAsync(user);

        //    var client = new SmtpClient(_smtpServer, _smtpPort)
        //    {
        //        Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
        //        EnableSsl = true
        //    };

        //    var mailMessage = new MailMessage
        //    {
        //        From = new MailAddress(_fromEmail),
        //        Subject = "Your Verification Code",
        //        Body = $@"
        //<h2>Password Reset Code</h2>
        //<p>Your OTP is: <strong>{verificationCode}</strong></p>
        //<p>This code is valid for 5 minutes.</p>
        //<br>
        //<p>Best regards,</p>
        //<p>Your Company Team</p>",
        //        IsBodyHtml = true
        //    };

        //    mailMessage.To.Add(user.Email);
        //    await client.SendMailAsync(mailMessage);
        //}

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string message)
        {
            try
            {
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress("TrueTone", _emailFrom));
                email.To.Add(new MailboxAddress("", toEmail));
                email.Subject = subject;
                //email.Body = new TextPart("plain") { Text = message };
                email.Body = new TextPart("html") { Text = $"<p>Your OTP code is: <strong>{message}</strong></p>" };


                using var smtp = new MailKit.Net.Smtp.SmtpClient();
                await smtp.ConnectAsync(_smtpServer, _smtpPort, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync(_emailFrom, _emailPassword);
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending email: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> VerifyCodeAsync(string email, string code)
        {
            var user = await _userManager.FindByEmailAsync(email);

            // تحقق من وجود المستخدم أولًا
            if (user == null)
            {
                Console.WriteLine("User not found");
                return false;
            }

            if (string.IsNullOrWhiteSpace(code))
            {
                Console.WriteLine("Code is empty");
                return false;
            }

            if (user.OtpCode == null || user.CodeExpiryTime == null || user.CodeExpiryTime < DateTime.UtcNow)
            {
                Console.WriteLine("OTP expired or missing");
                return false;
            }

            if (user.OtpCode != code)
            {
                Console.WriteLine("OTP does not match");
                return false;
            }

            user.OtpCode = null!;
            user.CodeExpiryTime = null;
            await _userManager.UpdateAsync(user);

            return true;
        }

    }
}
