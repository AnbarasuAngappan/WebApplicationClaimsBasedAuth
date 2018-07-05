using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApplicationClaimsBasedAuth.Controllers
{
   /* [Authorize(Roles = "anbu@gmail.com")]*/ //[Authorize(Roles = "Admin")]
    public class HomeController : Controller
    {
        [Authorize(Roles = "anbu@gmail.com")]
        public ActionResult Index()
        {
            ViewBag.Message = "Your Login By User Roles Admin Claim";
            return View();
        }

        [Authorize(Roles = "balaji@gmail.com")]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        [Authorize(Roles = "indhu@gmail.com")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}