using System.ComponentModel.DataAnnotations;
namespace AuthenticationServize.DTO.Account
{
    public class OtpRequest
    {
        [Required]
        public string PhoneNumber { get; set; }
    }
}
