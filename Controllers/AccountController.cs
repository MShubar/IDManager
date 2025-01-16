
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using IdentityManager.Models.ViewModels.LoginVM;
using IdentityManager.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
    //Add To github
        [Authorize]
        public class AccountController : Controller
        {

            private readonly UserManager<ApplicationUser> _userManager;
            private readonly RoleManager<IdentityRole> _roleManager;
            private readonly SignInManager<ApplicationUser> _signInManager;
            private readonly IEmailSender _emailSender;
            private readonly UrlEncoder _urlEncoder;
            public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
                IEmailSender emailSender, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
            {
                _emailSender = emailSender;
                _urlEncoder = urlEncoder;
                _signInManager = signInManager;
                _userManager = userManager;
                _roleManager = roleManager;
            }

            [AllowAnonymous]
            public async Task<IActionResult> Register(string returnurl = null)
            {
                if (!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
                {
                    await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
                    await _roleManager.CreateAsync(new IdentityRole(SD.User));
                }


                ViewData["ReturnUrl"] = returnurl;
                RegisterViewModel registerViewModel = new()
                {
                    RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                    {
                        Text = i,
                        Value = i
                    })
                };
                return View(registerViewModel);
            }

            [HttpPost]
            [AllowAnonymous]
            [ValidateAntiForgeryToken]
            public async Task<IActionResult> Register(RegisterViewModel model, string returnurl = null)
            {
                ViewData["ReturnUrl"] = returnurl;
                returnurl = returnurl ?? Url.Content("~/");
                if (ModelState.IsValid)
                {
                    var user = new ApplicationUser
                    {
                        UserName = model.Email,
                        Email = model.Email,
                        Name = model.Name,
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        if (model.RoleSelected != null)
                        {
                            await _userManager.AddToRoleAsync(user, model.RoleSelected);
                        }
                        else
                        {
                            await _userManager.AddToRoleAsync(user, SD.User);
                        }

                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var callbackurl = Url.Action("ConfirmEmail", "Account", new
                        {
                            userid = user.Id,
                            code
                        }, protocol: HttpContext.Request.Scheme);

                        await _emailSender.SendEmailAsync(model.Email, "Confirm Email - Identity Manager",
                                               $"Please confirm your email by clicking here: <a href='{callbackurl}'>link</a>");

                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnurl);
                    }

                    AddErrors(result);
                }
                model.RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                {
                    Text = i,
                    Value = i
                });
                return View(model);
            }
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        /*===================================================================*/
        /*-------------------------Login-------------------------------------*/
        [AllowAnonymous]
        public IActionResult Login(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,
                    lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.GetUserAsync(User);
                    var claim = await _userManager.GetClaimsAsync(user);

                    if (claim.Count > 0)
                    {
                        await _userManager.RemoveClaimAsync(user, claim.FirstOrDefault(u => u.Type == "FirstName"));
                    }
                    await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("FirstName", user.Name));

                    return LocalRedirect(returnurl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl, model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }

                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }
            return View(model);
        }

        /*===================================================================*/
        /*-------------------------Lockout-----------------------------------*/
        [HttpGet]
        public IActionResult Lockout()
        {
            return View();
        }
        /*===================================================================*/

        /*-------------------------Logout------------------------------------*/
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        /*===================================================================*/
        /*-----------------------Forget Password-----------------------------*/
        [HttpGet]
        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgetPasswordConformation");
                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new
                {
                    userId = user.Id,
                    code,
                }, protocol: HttpContext.Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Reset Password - Identity Manager",
                                       $"Please reset your password by clicking here: <a href='{callbackurl}'>link</a>");

                return RedirectToAction(nameof(ForgetPasswordConformation));
            }
            return View(model);
        }
        [HttpGet]
        public IActionResult ForgetPasswordConformation()
        {
            return View();
        }
        /*===================================================================*/
        /*------------------------Reset Password-----------------------------*/
        [HttpGet]
        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid Email ");
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(ResetPasswordConformation));
                }

            }
            return View();
        }

        [HttpGet]
        public IActionResult ResetPasswordConformation()
        {
            return View();
        }
        /*===================================================================*/
        /*------------------------Reset Password-----------------------------*/
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string code, string userId)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid User ");
                }
                var result = await _userManager.ConfirmEmailAsync(user, code);

                if (result.Succeeded)
                {
                    return View();
                }

            }
            return View("Error");
        }
        /*===================================================================*/
        /*------------------------EnableAuthenticator-----------------------------*/
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new TwoFactorAuthenticationViewModel() { Token = token };

            return View(model);
        }
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code could not be validated.");
                    return View(model);
                }
                return RedirectToAction(nameof(AuthenticatorConfirmation));
            }

            return View("Error");
        }
        /*===================================================================*/
        /*------------------------VerifyAuthenticatorCode-----------------------------*/
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;

            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });

        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {

            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe,
                rememberClient: false);
            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
        }
        /*===================================================================*/
        /*------------------------VerifyAuthenticatorCode-----------------------------*/

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }
        [HttpGet]
        public IActionResult Error()
        {
            return View();
        }
    }
}
