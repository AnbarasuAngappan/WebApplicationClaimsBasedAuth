using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebApplicationClaimsBasedAuth.Startup))]
namespace WebApplicationClaimsBasedAuth
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);          
            
        }
    }
}
