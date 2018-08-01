using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityServer.Attribute
{
    /// <summary>
    /// 设置安全过滤器特性
    /// </summary>
    public class SecurityHeadersAttribute : ActionFilterAttribute
    {
        /// <summary>
        /// 生成视图前
        /// </summary>
        /// <param name="context">报文</param>
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            IActionResult result = context.Result;
            if (result is ViewResult)
            {
                // 禁用客户端的 MIME 类型嗅探行为
                // https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Content-Type-Options
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Type-Options"))
                {
                    context.HttpContext.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                }

                // 该页面可以在相同域名页面的 frame 中展示
                // https://developer.mozilla.org/zh-CN/docs/Web/HTTP/X-Frame-Options
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Frame-Options"))
                {
                    context.HttpContext.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
                }

                // HTTP 响应头 Content-Security-Policy 允许站点管理者在指定的页面控制用户代理的资源。除了少数例外，这条政策将极大地限制服务源以及脚本端点。这将帮助防止跨站脚本攻击（Cross-Site Script） (XSS).
                // https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Content-Security-Policy__by_cnvoid
                string csp = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; sandbox allow-forms allow-same-origin allow-scripts; base-uri 'self';";
                // 如果在生产环境中让浏览器自动将 HTTP 请求转变为 HTTPS 请求，请使用以下语句：
                // csp += "upgrade-insecure-requests;";
                // 如果您需要限制只从 Twitter 显示客户端图像，请使用以下语句：
                // csp += "img-src 'self' https://pbs.twimg.com;";

                // 添加对浏览器的支持
                if (!context.HttpContext.Response.Headers.ContainsKey("Content-Security-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("Content-Security-Policy", csp);
                }
                // 添加对 IE 浏览器的支持
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Security-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("X-Content-Security-Policy", csp);
                }

                // 整个 Referer  首部会被移除。访问来源信息不随着请求一起发送。
                // https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Referrer-Policy
                string referrer_policy = "no-referrer";
                if (!context.HttpContext.Response.Headers.ContainsKey("Referrer-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("Referrer-Policy", referrer_policy);
                }
            }

        }
    }
}
