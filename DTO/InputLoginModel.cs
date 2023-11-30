namespace Makaan.DTO
{
    public class InputLoginModel
    {
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public string Role { get; set; }
        public bool IsMobileProvider { get; set; }
    }
}
