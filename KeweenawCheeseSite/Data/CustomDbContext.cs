using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class CustomDbContext : DbContext
    {
        public static string ConnectionString { get; set; }

        public DbSet<DiscordUser> DiscordUsers { get; set; }

        public CustomDbContext(DbContextOptions options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<DiscordUser>().ToTable("discordlogin");
        }

        public static CustomDbContext CreateContext()
        {
            var options = new DbContextOptionsBuilder<CustomDbContext>();
            options.UseMySQL(ConnectionString);

            return new CustomDbContext(options.Options);
        }
    }
}
