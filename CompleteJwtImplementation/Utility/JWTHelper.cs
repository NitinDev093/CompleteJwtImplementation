using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace CompleteJwtImplementation.Utility
{
    public class JWTHelper
    {
        private static string SecretKey = "ThisIsMySecretKey12345";
        private static string Issuer = "JobPortalAPI";
        private static string Audience = "JobPortalUsers";
        private static int ExpireMinutes = 60;

        // ===============================
        // GENERATE TOKEN (LOGIN TIME)
        // ===============================
        public static string GenerateToken(DataTable userModel, int expiryTime = 60)
        {
            
            string userdata = JsonConvert.SerializeObject(userModel);
            var symmetricKey = Encoding.UTF8.GetBytes(SecretKey);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, userdata)
                }),
                Expires = DateTime.UtcNow.AddMinutes(expiryTime),
                Issuer = Issuer,
                Audience = Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(symmetricKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(stoken);
        }

        // ===============================
        // VALIDATE TOKEN
        // ===============================
        public static ClaimsPrincipal ValidateToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(SecretKey);
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = Issuer,
                ValidAudience = Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero
            };
            SecurityToken validatedToken;
            return handler.ValidateToken(token, parameters, out validatedToken);
        }

        // ===============================
        // GET TOKEN FROM HEADER
        // ===============================
        public static string GetTokenFromHeader()
        {
            var authHeader = HttpContext.Current.Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authHeader))
                return null;
            return authHeader.Replace("Bearer ", "");
        }

        // ===============================
        // CHECK TOKEN EXPIRED
        // ===============================
        public static bool IsTokenExpired(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken.ValidTo < DateTime.UtcNow;
        }

        // ===============================
        // GET USER DATA (JSON) FROM TOKEN
        // ===============================
        public static string GetUserId(string token)
        {
            var principal = ValidateToken(token);
            return principal.FindFirst("UserId")?.Value;
        }

        public static string GetUserEmail(string token)
        {
            var principal = ValidateToken(token);
            return principal.FindFirst(ClaimTypes.Email)?.Value;
        }
    }
}
