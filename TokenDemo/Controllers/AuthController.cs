﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using TokenDemo.Data;
using TokenDemo.Model;

namespace TokenDemo.Controllers
{
    [Route("api/[controller]")]
    [EnableCors("_myAllowSpecificOrigins")]
    public class AuthController : Controller
    {
        private UserManager<ApplicationUser> userManager;

        public AuthController(UserManager<ApplicationUser> userManager)
        {
            this.userManager = userManager;
        }

        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);

            if(user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iss, "http://oec.com")
                };

                var signinKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperSecureKey"));

                var token = new JwtSecurityToken(
                    //issuer: "http://oec.com",
                    audience: "http://oec.com",
                    expires: DateTime.UtcNow.AddHours(1),
                    claims: claims,
                    signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(signinKey, SecurityAlgorithms.HmacSha256));

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            };

            return Unauthorized();
        }
    }
}