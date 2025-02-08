using ApiWithRoles.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ApiWithRoles.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            var user = new IdentityUser { UserName = model.Username };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok(new { message = "User registered successfully" });
            }
            return BadRequest(result.Errors);
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim> {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? string.Empty),  // safer null check
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                // Safely parse configuration values
                var issuer = _configuration["Jwt:Issuer"];
                var key = _configuration["Jwt:Key"];

                if (!double.TryParse(_configuration["Jwt:ExpireMinutes"], out var expireMinutes))
                {
                    expireMinutes = 60;  // Default expiration time if parsing fails
                }

                if (!string.IsNullOrEmpty(issuer) && !string.IsNullOrEmpty(key))
                {
                    var token = new JwtSecurityToken(
                        issuer: issuer,
                        //audience: audience,
                        expires: DateTime.Now.AddMinutes(expireMinutes),
                        claims: authClaims,
                        signingCredentials: new SigningCredentials(
                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                            SecurityAlgorithms.HmacSha256)
                    );

                    return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
                }
                else
                {
                    // Handle missing configuration values
                    return BadRequest("Invalid JWT configuration.");
                }
            }

            //return Unauthorized();
            return Unauthorized(new { message = "Invalid username or password." });
        }

        
        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            if (string.IsNullOrWhiteSpace(role))
            {
                return BadRequest("Role cannot be null or empty");
            }

            if (!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new { message = "Role added successfully" });
                }
                return BadRequest(result.Errors);
            }
            return BadRequest("Role already exists");
        }


        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user == null) {
                return BadRequest("User not found");
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded) {
                return Ok(new { message = "Role assigned successfully" });
            }
            return BadRequest(result.Errors);
        }

    }
}
