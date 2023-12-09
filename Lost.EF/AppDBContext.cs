using Lost.Core.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lost.EF
{
    public class AppDBContext:IdentityDbContext<User>
    {
        public AppDBContext(DbContextOptions<AppDBContext>options):base(options) { }



        public DbSet<User> User { get; set; }
        public DbSet<User> Admin { get; set; }
    }
}
