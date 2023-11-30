namespace Makaan.DTO
{
    public class AuthSuccessResponse
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
       // public UserMetaData MetaData { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}
