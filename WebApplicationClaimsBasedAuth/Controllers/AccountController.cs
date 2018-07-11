using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using WebApplicationClaimsBasedAuth.Data;
using WebApplicationClaimsBasedAuth.Models;

namespace WebApplicationClaimsBasedAuth.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

     

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            //LoginViewModel loginViewModel = new LoginViewModel();

            //loginViewModel.UserClaims = ClaimData.UserClaims.Select(c => new SelectListItem
            //{
            //    Text = c,
            //    Value = c
            //}).ToList();

            ViewBag.ReturnUrl = returnUrl;
            return View();//loginViewModel
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            #region
            //if (ModelState.IsValid)
            //{
            //    string userName = model.Email; //(string)Session["UserName"];
            //    string[] userRoles = { "anbu@gmail.com", "balaji@gmail.com", "indhu@gmail.com" };// (string[])Session["UserRoles"];

            //    ClaimsIdentity identity = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie);

            //    //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userName));
            //    identity.AddClaim(new Claim(ClaimTypes.Email, userName));
            //    userRoles.ToList().ForEach((role) => identity.AddClaim(new Claim(ClaimTypes.Role, role)));
            //    identity.AddClaim(new Claim(ClaimTypes.Name, userName));

            //    AuthenticationManager.SignIn(identity);
            //    return RedirectToAction(returnUrl);//"Success"
            //}
            //else
            //{
            //    return View("Login", model);
            //}

            //var user = UserManager.Find(model.Email, model.Password);
            //if (user != null)
            //{
            //    var identity = UserManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);

            //    identity.AddClaims(new[] {
            //                                new Claim(ClaimTypes.Email,model.Email),//"MyClaimName","MyClaimValue"
            //                                new Claim(ClaimTypes.Role,"CanEdit"),//"YetAnotherClaim","YetAnotherValue"
            //                              });
            //    AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true },identity);
            //    return RedirectToLocal(returnUrl);
            //}
            //ModelState.AddModelError("", "Invalid login attempt.");
            //return View(model);

            //---

            //List<SelectListItem> userClaims = model.UserClaims.Where(c => c.Selected).ToList();
            //foreach (var claim in userClaims)
            //{
            //    //user.Claims.Add(new IdentityUserClaim<string>
            //    //{
            //    //    ClaimType = claim.Value,
            //    //    ClaimValue = claim.Value
            //    //});
            //    user.Claims.Add(new IdentityUserClaim
            //    {
            //        ClaimType = claim.Value,
            //        ClaimValue = claim.Value
            //    });

            //}
            #endregion

            string[] vs = new string[100];           
            string userName = model.Email;
            var user = await UserManager.FindByNameAsync(model.Email);//User.Identity.Name)          Validating the User ID  
            var password = await UserManager.CheckPasswordAsync(user, model.Password);// Validating the Password
            if ((user != null && user.UserName.Length > 0) && password == true)
            {
                var claims = await UserManager.GetClaimsAsync(user.Id);
                var roles = claims.Where(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").ToList(); // to check the role of the user..

                #region
                //for (int i = 0; i < roles.Count; i++)
                //{
                //    vs[i] = roles.
                //}


                //string[] roles = GetRolesForUser(User.Identity.Name);
                //var id = ClaimsPrincipal.Current.Identities.First();
                //foreach (var role in roles)
                //{
                //    id.Claims.Add(new Claim(ClaimTypes.Role, role));
                //}




                //var claimss = new List<Claim>
                //    {
                //        new Claim(ClaimTypes.Role, roles)
                //    };


                //var claimrole = ""; //= roles.Value.ToString();
                //var claimType = "";// roles.Type.ToString();
                //var claimrole = roles.FirstOrDefault(c => c.Value == model.Email);//Value.ToString();
                //var claimType = roles.FirstOrDefault(c => c.Type == "");
                //var user1 = _context.Users.Single(x => x.Id == ...);
                //var role = UserManager.Roles.Single(x => x.Id == user.Roles.ElementAt(0).RoleId);
                //var claims = _roleManager.GetClaimsAsync(role).Result;
                #endregion

                if (!ModelState.IsValid)
                {
                    return View(model);
                }

              

                //foreach (var item in roles)
                //{

                //}

                var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, model.Email)},
                                                       DefaultAuthenticationTypes.ApplicationCookie, ClaimTypes.Name, ClaimTypes.Role);
                identity.AddClaim(new Claim(ClaimTypes.Email, userName));
                foreach (var item in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, item.Value));
                    //user.Claims.Add(new IdentityUserClaim());
                }
                //identity.AddClaim(new Claim(ClaimTypes.Role, model.Email));
                //identity.AddClaim(new Claim(ClaimTypes.Country, "India"));
                //identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                //identity.AddClaim(new Claim(claimType, claimrole));
                //identity.AddClaim(new Claim(ClaimTypes.Sid, "123"));
                //var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
                AuthenticationManager.SignIn(new AuthenticationProperties { IsPersistent = model.RememberMe }, identity);
                return RedirectToLocal(returnUrl, "");//claimrole



                #region
                //new AuthenticationProperties { AllowRefresh = false }, 

                //ClaimsIdentity claimsIdentity = new ClaimsIdentity();
                //bool a = identity.HasClaim(roles.Type, roles.Value);



                //if ((ClaimsIdentity)User.Identity).HasClaim("role", "miAdmin")
                //        {

                //}

                //, RedirectUri = "Employees/canCreateView"

                //if(claimrole == model.Email)
                //{
                //    return RedirectToAction("Index", "Home");
                //}
                //else if(claimrole == model.Email)
                //{
                //    return RedirectToAction("About", "Home");
                //}
                //else if (claimrole == model.Email)
                //{
                //    return RedirectToAction("Contact", "Home");
                //}
                //else
                //return RedirectToLocal(returnUrl,claimrole);
                #endregion
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }


            #region
            //---

            //if (!ModelState.IsValid)
            //{
            //    return View(model);
            //}

            //// This doesn't count login failures towards account lockout
            //// To enable password failures to trigger account lockout, change to shouldLockout: true
            //var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            //switch (result)
            //{
            //    case SignInStatus.Success:
            //        return RedirectToLocal(returnUrl);
            //    case SignInStatus.LockedOut:
            //        return View("Lockout");
            //    case SignInStatus.RequiresVerification:
            //        return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
            //    case SignInStatus.Failure:
            //    default:
            //        ModelState.AddModelError("", "Invalid login attempt.");
            //        return View(model);
            //}
            #endregion
        }


        //[HttpPost]
        //[ActionName("Login")]
        //public ActionResult Login(LoginViewModel model)
        //{

        //}


        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {

            RegisterViewModel model = new RegisterViewModel();
            model.UserClaims = ClaimData.UserClaims.Select(c => new SelectListItem
            {
                Text = c,
                Value = c
            }).ToList();

            return View(model);

           // return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email
                };
                string userRoles = null;
                List<SelectListItem> userClaims = model.UserClaims.Where(c => c.Selected).ToList();

                foreach (var item in userClaims)
                {
                    userRoles = item.Value;
                }


                var result = await UserManager.CreateAsync(user, model.Password);
                var claimaddresult = await UserManager.AddClaimAsync(user.Id, new Claim(ClaimTypes.Role, userRoles));//"newCustomClaim", "claimValue"                                                                                                                       
                //await UserManager.AddToRoleAsync(user.Id, "CanEdit");                                                                                                                        
                
                if (result.Succeeded && claimaddresult.Succeeded)
                {
                    //await SignInManager.SignInAsync(user, isPersistent:false, rememberBrowser:false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    //return RedirectToAction("Index", "Home");
                    return RedirectToAction("Login", "Account");
                }
                AddErrors(result,claimaddresult);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private void AddErrors(IdentityResult result,IdentityResult resultclaimadd)
        {
            if(result != null)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }

            }
            else
            {
                foreach (var error in resultclaimadd.Errors)
                {
                    ModelState.AddModelError("", error);
                }

            }
          
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("About", "Home");
        }


        private ActionResult RedirectToLocal(string returnUrl, string Role)
        {
            //if(Role != null && Role.Length > 0)
            //{              
            //    if(Role == "canCreate")
            //    {
            //        return RedirectToAction("canCreateView", "Employees");
            //    }
            //    else if(Role == "canEdit")
            //    {
            //        return RedirectToAction("CanEditView", "Employees");
            //    }   
                   

            //}
            return RedirectToAction("Index", "Home");
        }


        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }


        public ActionResult Getallclaimns()
        {
            //var x = User.Identity.GetUserId();
            var a = UserManager.FindByName(User.Identity.Name);           
            ViewBag.Message = UserManager.GetClaims(a.Id);
            return View();

            //return View(UserManager.GetClaims(User.Identity.GetUserId()));
        }
        #endregion
    }
}