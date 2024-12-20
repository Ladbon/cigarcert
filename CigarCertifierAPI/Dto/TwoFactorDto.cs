namespace CigarCertifierAPI.Dto
{
    public class TwoFactorDto
    {
        public required string Username { get; set; }
        public required string Token { get; set; }
    }
}