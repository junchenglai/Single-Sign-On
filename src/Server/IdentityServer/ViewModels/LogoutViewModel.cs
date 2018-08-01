using IdentityServer.Models;

namespace IdentityServer.ViewModels
{
    /// <summary>
    /// 
    /// </summary>
    public class LogoutViewModel : LogoutInputModel
    {
        /// <summary>
        /// 
        /// </summary>
        public bool ShowLogoutPrompt { get; set; }
    }
}
