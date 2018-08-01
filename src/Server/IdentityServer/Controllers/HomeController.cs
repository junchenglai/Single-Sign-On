using Microsoft.AspNetCore.Mvc;
using IdentityServer.ViewModels;
using IdentityServer.Attribute;
using System.Threading.Tasks;
using IdentityServer4.Services;

namespace IdentityServer.Controllers
{
    /// <summary>
    /// 首页控制器
    /// </summary>
    [SecurityHeaders]
    [Route("")]
    [Route("[controller]")]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;

        /// <summary>
        /// 
        /// </summary>
        public HomeController(IIdentityServerInteractionService interaction)
        {
            _interaction = interaction;
        }

        /// <summary>
        /// 显示首页页面
        /// </summary>
        [HttpGet()]
        [HttpGet("[action]")]
        public IActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// 显示错误页面
        /// </summary>
        /// <param name="errorId"></param>
        /// <returns></returns>
        [HttpGet("[action]")]
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // 接收所有的错误信息详情
            var message = await _interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;
            }

            return View("Error", vm);
        }
    }
}
