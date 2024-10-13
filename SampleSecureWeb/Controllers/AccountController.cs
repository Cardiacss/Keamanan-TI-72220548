using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Query;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModel;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;

        public AccountController(IUser user)
        {
                _userData = user;
        }
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Register(RegistrationViewModel  registrationViewModel)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "Contributor"
                    };
                    _userData.registration(user);
                    return RedirectToAction("Index","Home");
                }
                
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
                
            }
            return View(registrationViewModel);
        }

        public ActionResult Login()
        {
            return View();  
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginviewmodel)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    var user = new User 
                    {
                        Username = loginviewmodel.Username,
                        Password = loginviewmodel.Password
                    };
                    var loginUser = _userData.login(user);

                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username)  
                    };
                    var identity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,principal, new AuthenticationProperties
                    {
                        IsPersistent = loginviewmodel.RememberLogin
                    });
                    
                        return RedirectToAction("Index","Home");
                    }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
            }
            return View(loginviewmodel);
        }

        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }

        // POST: /Account/ChangePassword
        [HttpPost]
        [Authorize]
        public IActionResult ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _userData.login(new User { Username = User.Identity.Name, Password = model.CurrentPassword });
                
                if (user != null)
                {
                    user.Password = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
                    _userData.UpdatePassword(user); // Implement this method in IUser
                    return RedirectToAction("Index", "Home");
                }

                ModelState.AddModelError(string.Empty, "Current password is incorrect.");
            }
            return View(model);
        }
    }
}
