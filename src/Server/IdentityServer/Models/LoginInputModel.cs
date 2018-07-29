using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ViewModels
{
    /// <summary>
    /// 用户输入登录模板
    /// </summary>
    public class LoginInputModel
    {
        /// <summary>
        /// 用户名（必需）
        /// </summary>
        [Required]
        public string Username { get; set; }

        /// <summary>
        /// 密码（必需）
        /// </summary>
        [Required]
        public string Password { get; set; }

        /// <summary>
        /// 是否记得登录信息
        /// </summary>
        public bool RememberLogin { get; set; }

        /// <summary>
        /// 返回路径
        /// </summary>
        public string ReturnUrl { get; set; }
    }
}
