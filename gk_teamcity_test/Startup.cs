using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Gk_teamcity_test.Startup))]
namespace Gk_teamcity_test
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
