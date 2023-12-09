using Lost.Core.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lost.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthModel> UserRegister(UserDto member);
        Task<AuthModel> AdminRegister(UserDto member);
        Task<AuthModel> Login(LoginDto model);    }
}
