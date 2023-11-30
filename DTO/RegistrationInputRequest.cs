using Core.Library.BaseModel;
using System.ComponentModel.DataAnnotations;

namespace Makaan.DTO
{
    public class RegistrationInputRequest
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
        [Required(ErrorMessage = "PhoneNumber is required")]
        public string PhoneNumber { get; set; }
        public int Code { get; set; }
        [Required]
        public string? Role { get; set; }
        public DeviceType DeviceType { get; set; } = DeviceType.MOBILE;

    }
}
