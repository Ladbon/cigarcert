using QRCoder;

namespace CigarCertifierAPI.Utilities
{
    public static class QrCodeHelper
    {
        public static string GenerateQrCodeUrl(string email, string secretKey, string issuer = "CigarCertifierAPI")
        {
            return $"otpauth://totp/{issuer}:{email}?secret={secretKey}&issuer={issuer}";
        }

        public static string GenerateQrCodeBase64(string qrCodeUrl, int size = 20, QRCodeGenerator.ECCLevel eccLevel = QRCodeGenerator.ECCLevel.Q)
        {
            using QRCodeGenerator qrGenerator = new();
            using QRCodeData qrCodeData = qrGenerator.CreateQrCode(qrCodeUrl, eccLevel);
            using PngByteQRCode qrCode = new(qrCodeData);
            return Convert.ToBase64String(qrCode.GetGraphic(size));
        }

    }
}
