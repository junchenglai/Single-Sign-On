using System.Collections.Generic;

namespace IdentityServer.Models
{
    /// <summary>
    /// 授权请求数据模板
    /// </summary>
    public class ConsentInputModel
    {
        /// <summary>
        /// 触发按钮
        /// </summary>
        public string Button { get; set; }

        /// <summary>
        /// 同意范围
        /// </summary>
        public IEnumerable<string> ScopesConsented { get; set; }

        /// <summary>
        /// 是否同意记住用户
        /// </summary>
        public bool RememberConsent { get; set; }

        /// <summary>
        /// 返回的路径
        /// </summary>
        public string ReturnUrl { get; set; }
    }
}
