using Core.Library.Etag;
using Core.Library;
using Makaan.Domain.Utilities;

var builder = WebApplication.CreateBuilder(args);
string _policyName = "MyPolicy";
// Add services to the container.
builder.Services.CustomCors(_policyName);
builder.Services.AddServiceDependencies();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
builder.Services.AddAuthenticationService();
builder.Services.AddControllers(option =>
{
    option.Filters.Add(new ETagAttribute(10));
}
).AddSessionStateTempDataProvider(); // controller Registered
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();
