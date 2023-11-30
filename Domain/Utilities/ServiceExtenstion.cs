using AuthenticationServize.Domain.Repository;
using Core.Library.Configurations;
using Core.Library.Email;
using Core.Library.OtpClient;
using Core.Library.Stripes;
using Makaan.Domain.Model;
using Microsoft.ApplicationInsights.AspNetCore.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Makaan.Domain.Utilities
{
    public static class ServiceExtenstion
    {

        public static IServiceCollection AddServiceDependencies(this IServiceCollection services)
        {
            services.AddDatabaseInServizeCollection();
            services.AddDependencyInServizeCollection();
            var options = new ApplicationInsightsServiceOptions
            {
                ConnectionString = Configuration.GetValue<string>("core_application_insight_connectionstring"),
                EnableQuickPulseMetricStream = false
            };
            services.AddMvcCore();
            services.AddApplicationInsightsTelemetry(options);
            return services;
        }
       // Server=localhost\SQLEXPRESS;Database=master;Trusted_Connection=True;

        public static IServiceCollection AddDatabaseInServizeCollection(this IServiceCollection services)
        {
            string dbName = Configuration.GetValue<string>("app_database_name");

            string connectionString = $@"Server={Configuration.GetValue<string>("app_database_server")};
                                       Database={dbName};
                                       User Id = {Configuration.GetValue<string>("app_database_userid")};
                                       Password ={Configuration.GetValue<string>("app_database_password")};
                                       SslMode=VerifyFull";
            //Database connection
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));
            services.AddHealthChecks().AddDbContextCheck<ApplicationDbContext>();
            return services;
        }
        public static IServiceCollection AddDependencyInServizeCollection(this IServiceCollection services)
        {
           
            services.AddScoped<AccountRepository>();
            services.AddScoped<OtpGenerator>();
            services.AddScoped<EmailService>();
            services.AddGrpc();
            services.AddIdentity<User, IdentityRole>(options =>
            {
                options.User.RequireUniqueEmail = true;
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddRoles<IdentityRole>()
                .AddSignInManager()
                .AddDefaultTokenProviders()
                .AddTokenProvider("ServizeApp", typeof(DataProtectorTokenProvider<User>));
            return services;
        }
    }
}
