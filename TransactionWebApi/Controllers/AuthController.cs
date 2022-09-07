using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;
using TransactionWebApi.Models;
using TransactionWebApi.Dtos;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;



namespace TransactionWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AuthController : ControllerBase
    {
        //multiple inheritance is possible in C++ but it's not possible in C#.
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)=> _configuration = configuration;
        public static User user = new User();
        public static JwtToken auth = new JwtToken();

        [HttpPost("register")]
        //Action Result is a return type. This return type has many other derived types
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.username = request.Username;
            user.passwordHash = passwordHash;
            user.passwordSalt = passwordSalt;
            user.email = request.Email;
            return Ok(user);
        }
        [HttpPost("login")]
        //The Task class represents a sin8g gle operation that does not return a value and that usually executes asynchronously
        public async Task<ActionResult<JwtToken>> Login(UserDto request)
        {
            if (user.username != request.Username)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(request.Password, user.passwordHash, user.passwordSalt))
            {
                return BadRequest("Worng password...");
            }
            string token = CreateToken(user);
            auth.jwt = token;
            auth.roles = new string[] { "ROLE_ADMIN", "ROLE_MODERATOR" };
            return Ok(auth);
        }
        // C# List class represents a collection of strongly typed objects that can be accessed by index
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1));
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        //The out is a keyword in C# which is used for the passing the arguments to methods as a reference type
        //Private is Access modifiers in C# are used to specify the scope of accessibility of a member of a class or type of the class itself
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }

        }




    }
}
