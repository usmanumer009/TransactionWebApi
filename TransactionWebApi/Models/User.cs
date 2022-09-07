namespace TransactionWebApi.Models
{
    public class User
    {
        public string username { get; set; } = string.Empty;
        public byte[]? passwordHash { get; set; }
        public byte[]? passwordSalt { get; set; }
        public string? email { get; set; }
    }
}
