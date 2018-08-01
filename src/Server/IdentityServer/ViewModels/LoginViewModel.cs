using System;
using System.Collections.Generic;
using System.Linq;

namespace IdentityServer.ViewModels
{
    /// <summary>
    /// 
    /// </summary>
    public class LoginViewModel:LoginInputModel
    {
        /// <summary>
        /// 
        /// </summary>
        public bool AllowRememberLogin { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public bool EnableLocalLogin { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<ExternalProviderModel> ExternalProviders { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<ExternalProviderModel> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));

        /// <summary>
        /// 
        /// </summary>
        public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;
        /// <summary>
        /// 
        /// </summary>
        public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
    }
}
