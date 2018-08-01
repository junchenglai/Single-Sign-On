using IdentityServer.Models;
using System.Collections.Generic;

namespace IdentityServer.ViewModels
{
    /// <summary>
    /// 
    /// </summary>
    public class ConsentViewModel: ConsentInputModel
    {
        /// <summary>
        /// 
        /// </summary>
        public string ClientName { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string ClientUrl { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string ClientLogoUrl { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public bool AllowRememberConsent { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<ScopeViewModel> IdentityScopes { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<ScopeViewModel> ResourceScopes { get; set; }
    }
}
