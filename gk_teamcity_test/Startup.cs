using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(gk_teamcity_test.Startup))]
namespace gk_teamcity_test
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
