#pragma checksum "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\Account\Logout.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "0d342d3e7c3527c7b373b80c3ff44abd77ccfef3"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Account_Logout), @"mvc.1.0.view", @"/Views/Account/Logout.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Account/Logout.cshtml", typeof(AspNetCore.Views_Account_Logout))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\_ViewImports.cshtml"
using IdentityServer;

#line default
#line hidden
#line 2 "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\_ViewImports.cshtml"
using IdentityServer.Models;

#line default
#line hidden
#line 1 "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\Account\Logout.cshtml"
using IdentityServer.ViewModels;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"0d342d3e7c3527c7b373b80c3ff44abd77ccfef3", @"/Views/Account/Logout.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"10f39343255d883200aea98a2d0118731e125e0e", @"/Views/_ViewImports.cshtml")]
    public class Views_Account_Logout : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<LogoutViewModel>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Logout", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(58, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 4 "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\Account\Logout.cshtml"
   ViewData["Title"] = "注销"; 

#line default
#line hidden
            BeginContext(92, 188, true);
            WriteLiteral("\r\n<div class=\"logout-page\">\r\n    <div class=\"page-header\">\r\n        <h1>注销</h1>\r\n    </div>\r\n    <div class=\"row\">\r\n        <div class=\"col-sm-6\">\r\n            <p>您确定注销码？</p>\r\n            ");
            EndContext();
            BeginContext(280, 327, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "8f8c289a2fb945c580922a10a2fab8f5", async() => {
                BeginContext(306, 54, true);
                WriteLiteral("\r\n                <input type=\"hidden\" name=\"logoutId\"");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 360, "\"", 383, 1);
#line 14 "D:\实训\vote-collector\backend\SSO\src\Server\IdentityServer\Views\Account\Logout.cshtml"
WriteAttributeValue("", 368, Model.LogoutId, 368, 15, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(384, 216, true);
                WriteLiteral(" />\r\n                <fieldset>\r\n                    <div class=\"form-group\">\r\n                        <button class=\"btn btn-primary\">是</button>\r\n                    </div>\r\n                </fieldset>\r\n            ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(607, 36, true);
            WriteLiteral("\r\n        </div>\r\n    </div>\r\n</div>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<LogoutViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
