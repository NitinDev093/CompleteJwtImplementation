using CompleteJwtImplementation.Filters;
using CompleteJwtImplementation.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CompleteJwtImplementation.Controllers
{
    [JwtAuthorizeAttribute]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            string token = JWTHelper.GetTokenFromRequest();
            string email = JWTHelper.GetUserEmail(token);
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}