using System;

namespace IdentityServer.ViewModels
{
    /// <summary>
    /// 
    /// </summary>
    public class AccountOptions
    {
        /// <summary>
        /// 
        /// </summary>
        public static bool AllowLocalLogin = true;
        /// <summary>
        /// 
        /// </summary>
        public static bool AllowRememberLogin = true;
        /// <summary>
        /// 
        /// </summary>
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        /// <summary>
        /// 
        /// </summary>
        public static bool ShowLogoutPrompt = true;
        /// <summary>
        /// 
        /// </summary>
        public static bool AutomaticRedirectAfterSignOut = false;

        /// <summary>
        /// 指定正在使用的 Windows 身份验证方案
        /// </summary>
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;

        /// <summary>
        /// 如果用户使用Windows 身份验证，则在 Windows 中加载组
        /// </summary>
        public static bool IncludeWindowsGroups = false;

        /// <summary>
        /// 错误的验证信息
        /// </summary>
        public static string InvalidCredentialsErrorMessage = "错误的用户名或密码！";
    }
}
