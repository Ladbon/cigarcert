namespace CigarCertifierAPI.Utilities
{
    public static class DateTimeHelper
    {
        private static Func<DateTime> _utcNowProvider = () => DateTime.UtcNow;

        public static DateTime GetUtcNow() => _utcNowProvider();

        public static void SetUtcNowProvider(Func<DateTime> provider) => _utcNowProvider = provider;

        public static bool IsExpired(DateTime? expiryDate) => expiryDate == null || expiryDate < GetUtcNow();
    }

}
