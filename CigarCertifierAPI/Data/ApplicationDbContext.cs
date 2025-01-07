using CigarCertifierAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace CigarCertifierAPI.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; } = default!;
        public DbSet<Cigar> Cigars { get; set; } = default!;
        public DbSet<Certification> Certifications { get; set; } = default!;
        public DbSet<Manufacturer> Manufacturers { get; set; } = default!;
        public DbSet<BlacklistedToken> BlacklistedTokens { get; set; } = default!;
        public DbSet<ActiveToken> ActiveTokens { get; set; }

    }
}