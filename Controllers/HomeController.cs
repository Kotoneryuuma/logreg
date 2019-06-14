using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using login.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;


namespace login.Controllers
{
    public class HomeController : Controller
    {
        private MyContext dbContext;
        // here we can "inject" our context service into the constructor
        public HomeController(MyContext context)
        {
            dbContext = context;
        }

        
        [Route("")]
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }


        [HttpPost("register")]
        public IActionResult Register(User user)
        {
            // Check initial ModelState
            if(ModelState.IsValid)
            {
                // If a User exists with provided email
                if(dbContext.Users.Any(u => u.Email == user.Email))
                {
                    // Manually add a ModelState error to the Email field, with provided
                    // error message
                    ModelState.AddModelError("Email", "Email already in use!");
                    // You may consider returning to the View at this point
                }
                PasswordHasher<User> Hasher = new PasswordHasher<User>();
                User newUser = new User();
                newUser.FirstName = user.FirstName;
                newUser.LastName = user.LastName;
                newUser.Email = user.Email;
                newUser.Password = Hasher.HashPassword(user, user.Password);
                newUser.CreatedAt = DateTime.Now;
                newUser.UpdatedAt = DateTime.Now;
                dbContext.Add(newUser);
                dbContext.SaveChanges();

                User userInfo = dbContext.Users.OrderByDescending(u => u.CreatedAt).FirstOrDefault();
                HttpContext.Session.SetInt32("UserID", userInfo.UserId);

                return RedirectToAction("Success");
            }
            // other code
            else
                return View("Index");
        } 



         [HttpGet("login")]
        public IActionResult LoginForm()
        {
            return View("Login");
        }

        [Route("login")]
        [HttpPost]
        public IActionResult Login(LoginUser userSubmission)
        {
            var userInDb = dbContext.Users.FirstOrDefault(u => u.Email == userSubmission.Email);
            if (userInDb == null)
            {
                ModelState.AddModelError("Email", "Invalid Email/Password");
                return View("Login");
            }
            var Hasher = new PasswordHasher<LoginUser>();
            var result = Hasher.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.Password);
            if (result == 0)
            {
                ModelState.AddModelError("Password", "Invalid Email/Password");
            }
            if (!ModelState.IsValid)
            {
                return View("Login");
            }
            HttpContext.Session.SetInt32("UserID", userInDb.UserId);
            return RedirectToAction("Success");
        }

        
        [HttpGet("logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return Redirect("/");
        }


        [Route("success")]
        [HttpGet]
        public IActionResult Success()
        {
            return View("success");
        }
        
        

    }
}
