using CompleteJwtImplementation.Models;
using CompleteJwtImplementation.Utility;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CompleteJwtImplementation.Controllers
{
    [AllowAnonymous]
    public class UserController : Controller
    {
        string connectionstring = ConfigurationManager.ConnectionStrings["my_con"].ConnectionString;
        //Get
        public ActionResult Login()
        {
            return View();
        }

        public ActionResult UserLogin(string password,string email)
        {
            using (SqlConnection sqlcon = new SqlConnection(connectionstring))
            {
                SqlCommand cmd = new SqlCommand("usp_LoginMyUser", sqlcon);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@Email", email);
                cmd.Parameters.AddWithValue("@Password", password);
                DataTable dt = new DataTable();
                SqlDataAdapter sd = new SqlDataAdapter(cmd);
                sd.Fill(dt);
                if (dt.Rows.Count>0)
                {
                    string token = JWTHelper.GenerateToken(dt);
                    HttpCookie cookie = new HttpCookie("jwtToken", token);//for cookie
                    cookie.HttpOnly = true;//for cookie
                    cookie.Expires = DateTime.Now.AddMinutes(60);//for cookie
                    Response.Cookies.Add(cookie);//for cookie
                    return Json(new { success = true, message = "Login successfull" ,data=token}, JsonRequestBehavior.AllowGet);
                }
                else
                {
                    return Json(new { success = false, message = "Invalid username or password" }, JsonRequestBehavior.AllowGet);
                }
            }
        }

        public ActionResult LogOut()
        {
            Session["UserData"] = null;
            return View("Login");
        }

        public ActionResult SignUp()
        {
            return View();
        }

        public ActionResult InsertUserDetails(UserModal user)
        {
            try
            {
                using (SqlConnection sqlcon = new SqlConnection(connectionstring))
                {
                    SqlCommand cmd = new SqlCommand("usp_InsertMyUser", sqlcon);
                    cmd.CommandType=CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@FirstName", user.firstname);
                    cmd.Parameters.AddWithValue("@LastName", user.lastname);
                    cmd.Parameters.AddWithValue("@Email", user.email);
                    cmd.Parameters.AddWithValue("@Password", user.password);
                    cmd.Parameters.AddWithValue("@MobileNumber", user.mobilenumber);
                    sqlcon.Open();
                    int i = cmd.ExecuteNonQuery();
                    if (i > 0)
                    {
                        return Json(new { success = true, message = "Data saved Successfully" }, JsonRequestBehavior.AllowGet);
                    }
                    else
                    {
                        return Json(new { success = false, message = "Unable to save data" }, JsonRequestBehavior.AllowGet);
                    }
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Internal server error" }, JsonRequestBehavior.AllowGet);
            }

        }
    }
}