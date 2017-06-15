using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Gk_teamcity_test.Startup))]

namespace Gk_teamcity_test
{
    /// <summary>
    /// Start Up
    /// </summary>
    public partial class Startup
    {
        /// <summary>
        /// Configurations the specified application.
        /// </summary>
        /// <param name="app">The application.</param>
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
