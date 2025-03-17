// CodeGenerator.cs
namespace CigarCertifierAPI.Utilities
{
    public static class CodeGenerator
    {
        public static string GenerateNumericCode(int length)
        {
            var random = new Random();
            string code = string.Empty;
            for (int i = 0; i < length; i++)
            {
                code += random.Next(0, 10).ToString();
            }
            return code;
        }
    }
}
