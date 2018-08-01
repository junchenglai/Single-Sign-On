using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models
{
    public class SignupInputModel
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
        /// 手机号码（必须）
        /// </summary>
        [Required]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// 姓名
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// 电子邮箱地址
        /// </summary>
        public string Email { get; set; }

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
