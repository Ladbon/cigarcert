using CigarCertifierAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("api/[controller]")]
public class CigarsController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public CigarsController(ApplicationDbContext context)
    {
        _context = context;
    }

    // GET: api/Cigars
    [HttpGet]
    public async Task<ActionResult<IEnumerable<Cigar>>> GetCigars()
    {
        return await _context.Cigars.ToListAsync();
    }

    // Additional CRUD actions (POST, PUT, DELETE) go here
}
