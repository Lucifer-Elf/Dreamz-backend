using Microsoft.AspNetCore.Identity;
using System.ComponentModel;

namespace Makaan.Domain.Model
{
    public class User : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        [DefaultValue(false)]
        public bool IsDisabled { get; set; }

    }
}
