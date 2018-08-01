using IdentityServer.Models;

namespace IdentityServer.ViewModels
{
    public class SignupViewModel:SignupInputModel
    {
        public bool AllowRememberLogin { get; set; }

        public bool EnableLocalSignup { get; set; }
    }
}
