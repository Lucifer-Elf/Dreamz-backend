using Makaan.Domain.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Makaan.Domain
{
    public class ApplicationDbContext : IdentityDbContext<User>
    {
        public virtual DbSet<RefreshToken> RefreshToken { get; set; }
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<RefreshToken>(entity =>
            {
                entity.Property(i => i.Token).HasMaxLength(2000);
            });
            builder.Entity<User>().HasIndex(i => i.PhoneNumber).IsUnique();
            //builder.Entity<ApplicationUser>().HasIndex(i => i.Email).IsUnique();
            base.OnModelCreating(builder);
        }
    }
}
