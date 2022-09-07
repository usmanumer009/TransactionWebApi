namespace TransactionWebApi.Dtos
{
    public class JwtToken
    {
        public string? jwt { get; set; }
        public string[]? roles { get; set; }
    }
}
