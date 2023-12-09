using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lost.Core.Interfaces
{
    public interface IMailService
    {
        Task SendEmailAsync(string mailto, string subject,string body);
    }
}
