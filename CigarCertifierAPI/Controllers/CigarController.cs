using CigarCertifierAPI.Data;
using CigarCertifierAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CigarCertifierAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CigarsController(ApplicationDbContext context) : ControllerBase
    {
        private readonly ApplicationDbContext _context = context;

        // GET: api/Cigars
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Cigar>>> GetCigars()
        {
            return await _context.Cigars.ToListAsync();
        }

        // Additional CRUD actions (POST, PUT, DELETE) go here
    }
}