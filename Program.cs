using Microsoft.EntityFrameworkCore;
using TodoApi;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

try
{
    builder.Services.AddDbContext<ToDoDbContext>(options =>
        options.UseMySql(
            builder.Configuration.GetConnectionString("ToDoDB"), 
            new MySqlServerVersion(new Version(8, 0, 44))));
}
catch (Exception ex)
{
    Console.WriteLine($"❌ Database connection failed: {ex.Message}");
}

// ✅ וודא שה-Configuration variables קיימים
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
{
    throw new InvalidOperationException(
        "❌ JWT configuration is missing! Check Environment Variables in Render:\n" +
        $"  - Jwt__Key: {(string.IsNullOrEmpty(jwtKey) ? "❌ MISSING" : "✅ OK")}\n" +
        $"  - Jwt__Issuer: {(string.IsNullOrEmpty(jwtIssuer) ? "❌ MISSING" : "✅ OK")}\n" +
        $"  - Jwt__Audience: {(string.IsNullOrEmpty(jwtAudience) ? "❌ MISSING" : "✅ OK")}");
}

// הוספת שירותים ל-Dependency Injection
builder.Services.AddDbContext<ToDoDbContext>(options =>
    options.UseMySql(builder.Configuration.GetConnectionString("ToDoDB"), 
    new MySqlServerVersion(new Version(8, 0, 44))));

// הוספת שירותי CORS - מאפשר גישה מכל מקור
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy => policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader());
});

// הגדרת JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

// הוספת Swagger עם תמיכה ב-JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "TodoApi", Version = "v1" });
    
    // הוספת הגדרות JWT ל-Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// הגדרת Swagger (רק ב-Development)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "TodoApi V1");
        c.RoutePrefix = string.Empty; // Swagger יהיה זמין בכתובת הבית
    });
}

// שימוש ב-CORS
app.UseCors("AllowAll");

// הפעלת Authentication ו-Authorization
app.UseAuthentication();
app.UseAuthorization();

// ===== Routes ללא הזדהות =====

// Route להרשמת משתמש חדש
app.MapPost("/register", async (ToDoDbContext db, User newUser) =>
{
    // בדיקה אם המשתמש כבר קיים
    var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == newUser.Username);
    if (existingUser != null)
    {
        return Results.BadRequest(new { message = "Username already exists" });
    }
    
    // הצפנת הסיסמה (hash)
    newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password);
    
    db.Users.Add(newUser);
    await db.SaveChangesAsync();
    
    return Results.Created($"/users/{newUser.Id}", new { message = "User registered successfully" });
});

// Route להתחברות (Login)
app.MapPost("/login", async (ToDoDbContext db, LoginRequest loginRequest) =>
{
    // חיפוש המשתמש
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == loginRequest.Username);
    
    if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
    {
        return Results.Unauthorized();
    }
    
    // יצירת JWT Token
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        }),
        Expires = DateTime.UtcNow.AddHours(24),
        Issuer = builder.Configuration["Jwt:Issuer"],
        Audience = builder.Configuration["Jwt:Audience"],
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };
    
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);
    
    return Results.Ok(new { token = tokenString, username = user.Username });
});

// ===== Routes מוגנים עם JWT =====

// Route לשליפת כל המשימות (מוגן)
app.MapGet("/tasks", async (ToDoDbContext db) =>
    await db.Items.ToListAsync())
    .RequireAuthorization();

// Route להוספת משימה חדשה (מוגן)
app.MapPost("/tasks", async (ToDoDbContext db, Item item) =>
{
    db.Items.Add(item);
    await db.SaveChangesAsync();
    return Results.Created($"/tasks/{item.Id}", item);
})
.RequireAuthorization();

// Route לעדכון משימה (מוגן)
app.MapPut("/tasks/{id}", async (int id, ToDoDbContext db, Item updatedItem) =>
{
    var item = await db.Items.FindAsync(id);
    if (item is null) return Results.NotFound();
    
    item.Name = updatedItem.Name;
    item.IsComplete = updatedItem.IsComplete;
    
    await db.SaveChangesAsync();
    return Results.NoContent();
})
.RequireAuthorization();

// Route למחיקת משימה (מוגן)
app.MapDelete("/tasks/{id}", async (int id, ToDoDbContext db) =>
{
    var item = await db.Items.FindAsync(id);
    if (item is null) return Results.NotFound();

    db.Items.Remove(item);
    await db.SaveChangesAsync();
    return Results.NoContent();
})
.RequireAuthorization();

app.Run();

// מחלקה עזר ל-Login Request
public record LoginRequest(string Username, string Password);
