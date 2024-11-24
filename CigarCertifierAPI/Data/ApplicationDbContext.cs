using CigarCertifierAPI.Models;
using Microsoft.EntityFrameworkCore;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Cigar> Cigars { get; set; }
    public DbSet<Certification> Certifications { get; set; }
    public DbSet<Manufacturer> Manufacturers { get; set; }
}
