using CompleteJwtImplementation.Utility;
using System.Web.Mvc;
using System.Web.Routing;

namespace CompleteJwtImplementation.Filters
{
    public class JwtAuthorizeAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            // ✅ AllowAnonymous support
            bool skipAuthorization =
                filterContext.ActionDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true) ||
                filterContext.ActionDescriptor.ControllerDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true);

            if (skipAuthorization)
                return;

            try
            {
                string token = JWTHelper.GetTokenFromHeader();
                // Token missing
                if (string.IsNullOrEmpty(token))
                {
                    RedirectToLogin(filterContext);
                    return;
                }
                var principal = JWTHelper.ValidateToken(token);
                // Invalid or expired token
                if (principal == null || JWTHelper.IsTokenExpired(token))
                {
                    RedirectToLogin(filterContext);
                    return;
                }
                // ✅ Set current user context
                filterContext.HttpContext.User = principal;
            }
            catch
            {
                RedirectToLogin(filterContext);
            }
        }

        private void RedirectToLogin(AuthorizationContext filterContext)
        {
            filterContext.Result = new RedirectToRouteResult(
                new RouteValueDictionary(new
                {
                    controller = "User",
                    action = "Login"
                })
            );
        }
    }
}
