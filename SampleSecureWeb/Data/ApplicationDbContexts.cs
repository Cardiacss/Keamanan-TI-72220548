using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using SampleSecureWeb.Models;

namespace SampleSecureWeb.Data
{
    public class ApplicationDbContexts : DbContext
    {
        public ApplicationDbContexts(DbContextOptions<ApplicationDbContexts>options) : base(options)
        {

        }
        public DbSet<Student> Students { get; set; } = null!;
        public DbSet<User> Users { get; set; } = null!;
    }
}