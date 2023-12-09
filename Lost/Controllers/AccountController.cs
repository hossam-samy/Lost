using Lost.Core.Dtos;
using Lost.Core.Interfaces;
using Lost.Core.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Text.Encodings.Web;

namespace Lost.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAuthService authService;
        private readonly IMailService mailService;

        public AccountController(IAuthService authService, IMailService mailService)
        {
            this.authService = authService;
            this.mailService = mailService;
        }
        [HttpPost]
        public async Task<IActionResult> UserRegister([FromForm]UserDto User) { 
             if(!ModelState.IsValid) { return BadRequest(ModelState); }
             var result =await authService.UserRegister(User); 
            if(!result.IsAuthenticated)return BadRequest(result.Message);
            return Ok(User);  
        }
        [HttpPost]
        public async Task<IActionResult> AdminRegister([FromForm] UserDto User)
        {
            if (!ModelState.IsValid) { return BadRequest(ModelState); }
            var result = await authService.AdminRegister(User);
            if (!result.IsAuthenticated) return BadRequest(result.Message);
            return Ok(User);
        }
        [HttpPost]
        public async Task<IActionResult> Login([FromForm] LoginDto User)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await authService.Login(User);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }
            return Ok(User);
        }

        [HttpPost]
        public async Task<IActionResult> ConfirmEmail([FromForm] MailRequestDto dto)
                {
            await mailService.SendEmailAsync(dto.ToEmail, dto.Subject, dto.Body);

            return Ok("good");

        }


    }
}
