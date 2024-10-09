using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
         [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userData.GetUserAsync(User);
            if (user != null)
            {
                var result = await _userData.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                if (result.Succeeded)
                {
                    return RedirectToAction("ChangePasswordConfirmation");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            ModelState.AddModelError(string.Empty, "An error occurred while changing the password.");
        }
        return View(model);
    }

    public IActionResult ChangePasswordConfirmation()
    {
        return View();
    }

    }
}
