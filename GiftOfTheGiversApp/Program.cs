using GiftOfTheGiversApp.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// ✅ Add services to the container.
builder.Services.AddControllersWithViews();

// ✅ Configure EF Core with SQL Server
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ✅ Add Cookie Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Users/Login";        // Redirect here if not logged in
        options.LogoutPath = "/Users/Logout";      // Redirect here on logout
        options.AccessDeniedPath = "/Users/Login"; // If access denied
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Session timeout
        options.SlidingExpiration = true; // Extend session on activity
    });

builder.Services.AddAuthorization();

// ✅ Add Session (if you want to store user info like FullName, Role)
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(60);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// ✅ Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// ✅ Enable Authentication + Authorization
app.UseAuthentication();
app.UseAuthorization();

// ✅ Enable Session
app.UseSession();

// ✅ Default route mapping
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
