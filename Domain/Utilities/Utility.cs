using static Core.Library.CoreEnums;

namespace Makaan.Domain.Utilities
{
    public class Utility
    {
        public static string GetRoleForstring(string role)
        {
            if (role.ToUpper() == "ADMIN")
                return UserRoles.Admin;          
            if (role.ToUpper() == "CUSTOMER")
                return UserRoles.Customer;
            return UserRoles.Customer;
        }
    }
}
