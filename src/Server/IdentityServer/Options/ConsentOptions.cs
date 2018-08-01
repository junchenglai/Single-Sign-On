namespace IdentityServer.Options
{
    /// <summary>
    /// 
    /// </summary>
    public class ConsentOptions
    {
        /// <summary>
        /// 
        /// </summary>
        public static bool EnableOfflineAccess = true;

        /// <summary>
        /// 
        /// </summary>
        public static string OfflineAccessDisplayName = "Offline Access";

        /// <summary>
        /// 
        /// </summary>
        public static string OfflineAccessDescription = "Access to your applications and resources, even when you are offline";

        /// <summary>
        /// 
        /// </summary>
        public static readonly string MustChooseOneErrorMessage = "You must pick at least one permission";

        /// <summary>
        /// 
        /// </summary>
        public static readonly string InvalidSelectionErrorMessage = "Invalid selection";
    }
}
