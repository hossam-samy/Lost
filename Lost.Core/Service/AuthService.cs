using Azure.Core;
using Lost.Core.Dtos;
using Lost.Core.Helpers;
using Lost.Core.Interfaces;
using Lost.Core.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Lost.Core.Service
{
    public class AuthService:IAuthService
    {
        private readonly UserManager<User> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly JWT jwt;
        

        public AuthService(UserManager<User> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.jwt = jwt.Value;
            this.roleManager = roleManager;
           
        }

        public async Task<AuthModel> Login(LoginDto model)
        {
            var auth = new AuthModel();
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user is null || !await userManager.CheckPasswordAsync(user, model.Password))
            {
                auth.Message = "Username or Password is wrong";
                return auth;
            }
            auth.Email = model.Email;
            auth.IsAuthenticated = true;
            auth.Username = user.UserName;
            var role = await userManager.GetRolesAsync(user);
            auth.Roles = role.ToList();
            var token = await CreateJwtToken(user);
            auth.Token = new JwtSecurityTokenHandler().WriteToken(token);

            return auth;
        }

        public async Task<AuthModel> UserRegister(UserDto model)
        {
            if (await userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel() { Message = "Email already exist " };

            if (await userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthModel() { Message = "Username already exist " };

            var user = new User
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                

            };
            
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += error.Description + " , ";
                }
                return new AuthModel() { Message = errors };
            }
            await userManager.AddToRoleAsync(user, "User");

            var jwtsecuritytoken = await CreateJwtToken(user);
            return new AuthModel()
            {
                Email = user.Email,
                IsAuthenticated = true,
                Username = user.UserName,
                Roles = new List<string> { "User" },
                ExpiresOn = jwtsecuritytoken.ValidTo,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtsecuritytoken)
            };

        }
        public async Task<AuthModel> AdminRegister(UserDto model)
        {
            if (await userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel() { Message = "Email already exist " };

            if (await userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthModel() { Message = "Username already exist " };

            var user = new Admin
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };
            var us = new User();
            us = user;

            var result = await userManager.CreateAsync(us, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += error.Description + " , ";
                }
                return new AuthModel() { Message = errors };
            }
            await userManager.AddToRoleAsync(us, "Admin");
            var jwtsecuritytoken = await CreateJwtToken(user);
            return new AuthModel()
            {
                Email = user.Email,
                IsAuthenticated = true,
                Username = user.UserName,
                Roles = new List<string> { "Admin" },
                ExpiresOn = jwtsecuritytoken.ValidTo,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtsecuritytoken),
                Id = jwtsecuritytoken.Id
            };

        }
        private async Task<JwtSecurityToken> CreateJwtToken(User user)
        {
            var userClaims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: jwt.Issuer,
                audience: jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(jwt.DurationInDay),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
     
    }
}
