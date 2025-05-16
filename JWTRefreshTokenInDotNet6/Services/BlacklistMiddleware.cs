namespace VoiceDetection.Services
{
    public class BlacklistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _scopeFactory;
        public BlacklistMiddleware(RequestDelegate next, IServiceScopeFactory scopeFactory)
        {
            _next = next;
            _scopeFactory = scopeFactory;
        }
        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (!string.IsNullOrEmpty(token))
            {
                using (var scope = _scopeFactory.CreateScope())
                {
                    var blacklistService = scope.ServiceProvider.GetRequiredService<IBlacklistService>();
                    var isBlacklisted = await blacklistService.IsTokenBlacklistedAsync(token);

                    if (isBlacklisted)
                    {
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Token is blacklisted.");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }

}
