// // using Microsoft.EntityFrameworkCore;
// // using TodoApi;
// // using Microsoft.OpenApi.Models;
// // using Microsoft.AspNetCore.Authentication.JwtBearer;
// // using Microsoft.IdentityModel.Tokens;
// // using System.Text;
// // using System.IdentityModel.Tokens.Jwt;
// // using System.Security.Claims;

// // var builder = WebApplication.CreateBuilder(args);


// // // הוספת שירותים ל-Dependency Injection
// // builder.Services.AddDbContext<ToDoDbContext>(options =>
// //     options.UseMySql(builder.Configuration.GetConnectionString("ToDoDB"), 
// //     new MySqlServerVersion(new Version(8, 0, 44))));

// // // הוספת שירותי CORS - מאפשר גישה מכל מקור
// // builder.Services.AddCors(options =>
// // {
// //     options.AddPolicy("AllowAll",
// //         policy => policy.AllowAnyOrigin()
// //                         .AllowAnyMethod()
// //                         .AllowAnyHeader());
// // });

// // // הגדרת JWT Authentication
// // var jwtKey = builder.Configuration["Jwt:Key"];
// // var jwtIssuer = builder.Configuration["Jwt:Issuer"];
// // var jwtAudience = builder.Configuration["Jwt:Audience"];

// // builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
// //     .AddJwtBearer(options =>
// //     {
// //         options.TokenValidationParameters = new TokenValidationParameters
// //         {
// //             ValidateIssuer = true,
// //             ValidateAudience = true,
// //             ValidateLifetime = true,
// //             ValidateIssuerSigningKey = true,
// //             ValidIssuer = jwtIssuer,
// //             ValidAudience = jwtAudience,
// //             IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
// //         };
// //     });

// // builder.Services.AddAuthorization();

// // // הוספת Swagger עם תמיכה ב-JWT
// // builder.Services.AddEndpointsApiExplorer();
// // builder.Services.AddSwaggerGen(c =>
// // {
// //     c.SwaggerDoc("v1", new OpenApiInfo { Title = "TodoApi", Version = "v1" });
    
// //     // הוספת הגדרות JWT ל-Swagger
// //     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
// //     {
// //         Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token",
// //         Name = "Authorization",
// //         In = ParameterLocation.Header,
// //         Type = SecuritySchemeType.ApiKey,
// //         Scheme = "Bearer"
// //     });
    
// //     c.AddSecurityRequirement(new OpenApiSecurityRequirement
// //     {
// //         {
// //             new OpenApiSecurityScheme
// //             {
// //                 Reference = new OpenApiReference
// //                 {
// //                     Type = ReferenceType.SecurityScheme,
// //                     Id = "Bearer"
// //                 }
// //             },
// //             Array.Empty<string>()
// //         }
// //     });
// // });

// // var app = builder.Build();

// // // הגדרת Swagger (רק ב-Development)
// // if (app.Environment.IsDevelopment())
// // {
// //     app.UseSwagger();
// //     app.UseSwaggerUI(c =>
// //     {
// //         c.SwaggerEndpoint("/swagger/v1/swagger.json", "TodoApi V1");
// //         c.RoutePrefix = string.Empty; // Swagger יהיה זמין בכתובת הבית
// //     });
// // }

// // // שימוש ב-CORS
// // app.UseCors("AllowAll");

// // // הפעלת Authentication ו-Authorization
// // app.UseAuthentication();
// // app.UseAuthorization();

// // // ===== Routes ללא הזדהות =====

// // // Route להרשמת משתמש חדש
// // app.MapPost("/register", async (ToDoDbContext db, User newUser) =>
// // {
// //     // בדיקה אם המשתמש כבר קיים
// //     var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == newUser.Username);
// //     if (existingUser != null)
// //     {
// //         return Results.BadRequest(new { message = "Username already exists" });
// //     }
    
// //     // הצפנת הסיסמה (hash)
// //     newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password);
    
// //     db.Users.Add(newUser);
// //     await db.SaveChangesAsync();
    
// //     return Results.Created($"/users/{newUser.Id}", new { message = "User registered successfully" });
// // });

// // // Route להתחברות (Login)
// // app.MapPost("/login", async (ToDoDbContext db, LoginRequest loginRequest) =>
// // {
// //     // חיפוש המשתמש
// //     var user = await db.Users.FirstOrDefaultAsync(u => u.Username == loginRequest.Username);
    
// //     if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
// //     {
// //         return Results.Unauthorized();
// //     }
    
// //     // יצירת JWT Token
// //     var tokenHandler = new JwtSecurityTokenHandler();
// //     var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]);
// //     var tokenDescriptor = new SecurityTokenDescriptor
// //     {
// //         Subject = new ClaimsIdentity(new[]
// //         {
// //             new Claim(ClaimTypes.Name, user.Username),
// //             new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
// //         }),
// //         Expires = DateTime.UtcNow.AddHours(24),
// //         Issuer = builder.Configuration["Jwt:Issuer"],
// //         Audience = builder.Configuration["Jwt:Audience"],
// //         SigningCredentials = new SigningCredentials(
// //             new SymmetricSecurityKey(key),
// //             SecurityAlgorithms.HmacSha256Signature)
// //     };
    
// //     var token = tokenHandler.CreateToken(tokenDescriptor);
// //     var tokenString = tokenHandler.WriteToken(token);
    
// //     return Results.Ok(new { token = tokenString, username = user.Username });
// // });

// // // ===== Routes מוגנים עם JWT =====

// // // Route לשליפת כל המשימות (מוגן)
// // app.MapGet("/tasks", async (ToDoDbContext db) =>
// //     await db.Items.ToListAsync())
// //     .RequireAuthorization();

// // // Route להוספת משימה חדשה (מוגן)
// // app.MapPost("/tasks", async (ToDoDbContext db, Item item) =>
// // {
// //     db.Items.Add(item);
// //     await db.SaveChangesAsync();
// //     return Results.Created($"/tasks/{item.Id}", item);
// // })
// // .RequireAuthorization();

// // // Route לעדכון משימה (מוגן)
// // app.MapPut("/tasks/{id}", async (int id, ToDoDbContext db, Item updatedItem) =>
// // {
// //     var item = await db.Items.FindAsync(id);
// //     if (item is null) return Results.NotFound();
    
// //     item.Name = updatedItem.Name;
// //     item.IsComplete = updatedItem.IsComplete;
    
// //     await db.SaveChangesAsync();
// //     return Results.NoContent();
// // })
// // .RequireAuthorization();

// // // Route למחיקת משימה (מוגן)
// // app.MapDelete("/tasks/{id}", async (int id, ToDoDbContext db) =>
// // {
// //     var item = await db.Items.FindAsync(id);
// //     if (item is null) return Results.NotFound();

// //     db.Items.Remove(item);
// //     await db.SaveChangesAsync();
// //     return Results.NoContent();
// // })
// // .RequireAuthorization();

// // app.Run();

// // // מחלקה עזר ל-Login Request
// // public record LoginRequest(string Username, string Password);

// using Microsoft.EntityFrameworkCore;
// using TodoApi;
// using Microsoft.OpenApi.Models;
// using Microsoft.AspNetCore.Authentication.JwtBearer;
// using Microsoft.IdentityModel.Tokens;
// using System.Text;
// using System.IdentityModel.Tokens.Jwt;
// using System.Security.Claims;

// var builder = WebApplication.CreateBuilder(args);

// // ✅ קריאת Configuration variables
// var connectionString = builder.Configuration.GetConnectionString("ToDoDB");
// var jwtKey = builder.Configuration["Jwt:Key"];
// var jwtIssuer = builder.Configuration["Jwt:Issuer"];
// var jwtAudience = builder.Configuration["Jwt:Audience"];

// // ✅ בדיקת Connection String
// if (string.IsNullOrEmpty(connectionString))
// {
//     throw new InvalidOperationException(
//         "❌ CONNECTION STRING IS MISSING!\n" +
//         "Check:\n" +
//         "  1. appsettings.json has 'ConnectionStrings:ToDoDB'\n" +
//         "  2. Render Environment has 'ConnectionStrings__ToDoDB'");
// }

// // ✅ בדיקת JWT Configuration
// if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
// {
//     throw new InvalidOperationException(
//         "❌ JWT configuration is missing! Check Environment Variables in Render:\n" +
//         $"  - Jwt__Key: {(string.IsNullOrEmpty(jwtKey) ? "❌ MISSING" : "✅ OK")}\n" +
//         $"  - Jwt__Issuer: {(string.IsNullOrEmpty(jwtIssuer) ? "❌ MISSING" : "✅ OK")}\n" +
//         $"  - Jwt__Audience: {(string.IsNullOrEmpty(jwtAudience) ? "❌ MISSING" : "✅ OK")}");
// }

// // ✅ הוספת DbContext עם Retry Logic
// builder.Services.AddDbContext<ToDoDbContext>(options =>
//     options.UseMySql(
//         connectionString,
//         ServerVersion.AutoDetect(connectionString),
//       mysqlOptions => mysqlOptions.EnableRetryOnFailure(
//     maxRetryCount: 3,
//     maxRetryDelay: TimeSpan.FromSeconds(5),  // ✅ CORRECT
//     errorNumbersToAdd: null
// )
//     )
// );

// // ✅ הוספת CORS
// builder.Services.AddCors(options =>
// {
//     options.AddPolicy("AllowAll",
//         policy => policy.AllowAnyOrigin()
//                         .AllowAnyMethod()
//                         .AllowAnyHeader());
// });

// // ✅ הגדרת JWT Authentication
// builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//     .AddJwtBearer(options =>
//     {
//         options.TokenValidationParameters = new TokenValidationParameters
//         {
//             ValidateIssuer = true,
//             ValidateAudience = true,
//             ValidateLifetime = true,
//             ValidateIssuerSigningKey = true,
//             ValidIssuer = jwtIssuer,
//             ValidAudience = jwtAudience,
//             IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
//         };
//     });

// builder.Services.AddAuthorization();

// // ✅ הוספת Swagger
// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen(c =>
// {
//     c.SwaggerDoc("v1", new OpenApiInfo { Title = "TodoApi", Version = "v1" });
    
//     c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
//     {
//         Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token",
//         Name = "Authorization",
//         In = ParameterLocation.Header,
//         Type = SecuritySchemeType.ApiKey,
//         Scheme = "Bearer"
//     });
    
//     c.AddSecurityRequirement(new OpenApiSecurityRequirement
//     {
//         {
//             new OpenApiSecurityScheme
//             {
//                 Reference = new OpenApiReference
//                 {
//                     Type = ReferenceType.SecurityScheme,
//                     Id = "Bearer"
//                 }
//             },
//             Array.Empty<string>()
//         }
//     });
// });

// var app = builder.Build();

// // ✅ הפעלת Swagger (גם בProd כדי לבדוק ב-Render)
// app.UseSwagger();
// app.UseSwaggerUI(c =>
// {
//     c.SwaggerEndpoint("/swagger/v1/swagger.json", "TodoApi V1");
//     c.RoutePrefix = string.Empty;
// });

// // ✅ הפעלת CORS
// app.UseCors("AllowAll");

// // ✅ הפעלת Authentication ו-Authorization
// app.UseAuthentication();
// app.UseAuthorization();

// // ===== Routes ללא הזדהות =====

// // Route להרשמת משתמש חדש
// app.MapPost("/register", async (ToDoDbContext db, User newUser) =>
// {
//     var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == newUser.Username);
//     if (existingUser != null)
//     {
//         return Results.BadRequest(new { message = "Username already exists" });
//     }
    
//     newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password);
    
//     db.Users.Add(newUser);
//     await db.SaveChangesAsync();
    
//     return Results.Created($"/users/{newUser.Id}", new { message = "User registered successfully" });
// });

// // Route להתחברות (Login)
// app.MapPost("/login", async (ToDoDbContext db, LoginRequest loginRequest) =>
// {
//     var user = await db.Users.FirstOrDefaultAsync(u => u.Username == loginRequest.Username);
    
//     if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
//     {
//         return Results.Unauthorized();
//     }
    
//     var tokenHandler = new JwtSecurityTokenHandler();
//     var key = Encoding.UTF8.GetBytes(jwtKey);
    
//     var tokenDescriptor = new SecurityTokenDescriptor
//     {
//         Subject = new ClaimsIdentity(new[]
//         {
//             new Claim(ClaimTypes.Name, user.Username),
//             new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
//         }),
//         Expires = DateTime.UtcNow.AddHours(24),
//         Issuer = jwtIssuer,
//         Audience = jwtAudience,
//         SigningCredentials = new SigningCredentials(
//             new SymmetricSecurityKey(key),
//             SecurityAlgorithms.HmacSha256Signature)
//     };
    
//     var token = tokenHandler.CreateToken(tokenDescriptor);
//     var tokenString = tokenHandler.WriteToken(token);
    
//     return Results.Ok(new { token = tokenString, username = user.Username });
// });

// // ===== Routes מוגנים עם JWT =====

// // Route לשליפת כל המשימות (מוגן)
// app.MapGet("/tasks", async (ToDoDbContext db) =>
//     await db.Items.ToListAsync())
//     .RequireAuthorization();

// // Route להוספת משימה חדשה (מוגן)
// app.MapPost("/tasks", async (ToDoDbContext db, Item item) =>
// {
//     db.Items.Add(item);
//     await db.SaveChangesAsync();
//     return Results.Created($"/tasks/{item.Id}", item);
// })
// .RequireAuthorization();

// // Route לעדכון משימה (מוגן)
// app.MapPut("/tasks/{id}", async (int id, ToDoDbContext db, Item updatedItem) =>
// {
//     var item = await db.Items.FindAsync(id);
//     if (item is null) return Results.NotFound();
    
//     item.Name = updatedItem.Name;
//     item.IsComplete = updatedItem.IsComplete;
    
//     await db.SaveChangesAsync();
//     return Results.NoContent();
// })
// .RequireAuthorization();

// // Route למחיקת משימה (מוגן)
// app.MapDelete("/tasks/{id}", async (int id, ToDoDbContext db) =>
// {
//     var item = await db.Items.FindAsync(id);
//     if (item is null) return Results.NotFound();

//     db.Items.Remove(item);
//     await db.SaveChangesAsync();
//     return Results.NoContent();
// })
// .RequireAuthorization();

// app.Run();

// // מחלקה עזר ל-Login Request
// public record LoginRequest(string Username, string Password);

using Microsoft.EntityFrameworkCore;
using TodoApi;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ✅ קריאת Configuration variables
var connectionString = builder.Configuration.GetConnectionString("ToDoDB");
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var environment = builder.Environment.EnvironmentName;
var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>();
var enableSwagger = builder.Configuration.GetValue<bool>("EnableSwagger", false);

// ✅ בדיקת Connection String
if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException(
        "❌ CONNECTION STRING IS MISSING!\n" +
        "Check:\n" +
        "  1. appsettings.json has 'ConnectionStrings:ToDoDB'\n" +
        "  2. Render Environment has 'ConnectionStrings__ToDoDB'");
}

// ✅ בדיקת JWT Configuration
if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer) || string.IsNullOrEmpty(jwtAudience))
{
    throw new InvalidOperationException(
        "❌ JWT CONFIGURATION IS MISSING!\n" +
        "Check Environment Variables");
}

// ✅ Logging
builder.Services.AddLogging(config =>
{
    config.ClearProviders();
    config.AddConsole();
    if (environment == "Development")
    {
        config.AddDebug();
    }
});

// ✅ DbContext
builder.Services.AddDbContext<ToDoDbContext>(options =>
    options.UseMySql(
        connectionString,
        new MySqlServerVersion(new Version(8, 0, 44)),
        mysqlOptions => mysqlOptions.EnableRetryOnFailure(
            maxRetryCount: 3,
            maxRetryDelay: TimeSpan.FromSeconds(5),
            errorNumbersToAdd: null
        )
    )
);

// ✅ Rate Limiting
builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    rateLimiterOptions.AddFixedWindowLimiter("login", options =>
    {
        options.PermitLimit = 5;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 2;
    });

    rateLimiterOptions.AddFixedWindowLimiter("register", options =>
    {
        options.PermitLimit = 3;
        options.Window = TimeSpan.FromMinutes(5);
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 1;
    });

    rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// ✅ CORS
// var corsOrigins = allowedOrigins ?? new[] { "http://localhost:3000" };

// builder.Services.AddCors(options =>
// {
//     options.AddPolicy("AllowSpecific",
//         policy => policy
//             .WithOrigins(corsOrigins)
//             .AllowCredentials()
//             .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
//             .WithHeaders("Authorization", "Content-Type", "Accept")
//             .SetPreflightMaxAge(TimeSpan.FromHours(1)));

//     if (environment == "Development")
//     {
//         options.AddPolicy("AllowAll",
//             policy => policy
//                 .AllowAnyOrigin()
//                 .AllowAnyMethod()
//                 .AllowAnyHeader());
//     }
// });
// ✅ CORS עם Frontend URL בענן
var corsOrigins = new[] 
{ 
    "https://todolistreact-frqz.onrender.com",  // ✅ הוסף את Frontend URL
    "http://localhost:3000"                       // עדיין צריך לפיתוח
};

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecific",
        policy => policy
            .WithOrigins(corsOrigins)
            .AllowCredentials()
            .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .WithHeaders("Authorization", "Content-Type", "Accept")
            .SetPreflightMaxAge(TimeSpan.FromHours(1)));

    if (environment == "Development")
    {
        options.AddPolicy("AllowAll",
            policy => policy
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());
    }
});

// ✅ JWT Authentication
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromSeconds(10)
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                context.NoResult();
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                var response = new { message = "Token validation failed", error = context.Exception.Message };
                var jsonResponse = System.Text.Json.JsonSerializer.Serialize(response);
                return context.Response.WriteAsync(jsonResponse);
            },
            OnForbidden = context =>
            {
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                var response = new { message = "Access forbidden" };
                var jsonResponse = System.Text.Json.JsonSerializer.Serialize(response);
                return context.Response.WriteAsync(jsonResponse);
            }
        };
    });

builder.Services.AddAuthorization();

// ✅ Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "TodoApi",
        Version = "v1",
        Description = "Todo API with JWT Authentication"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
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

// ✅ HTTPS Redirect
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// ✅ Swagger
if (enableSwagger || app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "TodoApi V1");
        c.RoutePrefix = string.Empty;
    });
}

// ✅ Middleware
app.UseRateLimiter();
app.UseCors(environment == "Development" ? "AllowAll" : "AllowSpecific");
app.UseAuthentication();
app.UseAuthorization();

// ✅ Global Exception Handling
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.ContentType = "application/json";
        var exceptionHandlerPathFeature = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerPathFeature>();
        var exception = exceptionHandlerPathFeature?.Error;
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();

        logger.LogError(exception, "Unhandled exception occurred");

        var statusCode = exception switch
        {
            ArgumentException => 400,
            UnauthorizedAccessException => 401,
            KeyNotFoundException => 404,
            _ => 500
        };

        context.Response.StatusCode = statusCode;
        var response = new
        {
            error = exception?.Message ?? "An unexpected error occurred",
            timestamp = DateTime.UtcNow,
            traceId = context.TraceIdentifier
        };

        await context.Response.WriteAsJsonAsync(response);
    });
});

// ===== Helper Functions =====

static bool IsValidPassword(string password)
{
    if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        return false;
    return password.Any(char.IsUpper) && password.Any(char.IsLower) && password.Any(char.IsDigit);
}

static (bool IsValid, string? Error) ValidateUsername(string? username)
{
    if (string.IsNullOrWhiteSpace(username))
        return (false, "Username is required");
    if (username.Length < 3 || username.Length > 50)
        return (false, "Username must be 3-50 characters");
    if (!System.Text.RegularExpressions.Regex.IsMatch(username, @"^[a-zA-Z0-9_.-]+$"))
        return (false, "Username can only contain letters, numbers, dots, dashes, and underscores");
    return (true, null);
}

// ===== ROUTES =====

// Health Check
app.MapGet("/health", () => Results.Ok(new { status = "healthy", environment = app.Environment.EnvironmentName, timestamp = DateTime.UtcNow }))
    .WithName("Health Check")
    .AllowAnonymous();

// Register
app.MapPost("/register", async (ToDoDbContext db, User newUser, ILogger<Program> logger) =>
{
    try
    {
        var (usernameValid, usernameError) = ValidateUsername(newUser.Username);
        if (!usernameValid)
            return Results.BadRequest(new { message = usernameError });

        if (string.IsNullOrWhiteSpace(newUser.Password))
            return Results.BadRequest(new { message = "Password is required" });

        if (!IsValidPassword(newUser.Password))
            return Results.BadRequest(new { message = "Password must be at least 8 characters with uppercase, lowercase, and digits" });

        var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == newUser.Username);
        if (existingUser != null)
            return Results.BadRequest(new { message = "Username already exists" });

        newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password);
        db.Users.Add(newUser);
        await db.SaveChangesAsync();

        logger.LogInformation("User registered: {Username}", newUser.Username);
        return Results.Created($"/users/{newUser.Id}", new { message = "User registered successfully", userId = newUser.Id });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error during registration");
        return Results.StatusCode(500);
    }
})
.WithName("Register User")
.AllowAnonymous()
.RequireRateLimiting("register")
.Produces(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status429TooManyRequests)
.Produces(StatusCodes.Status500InternalServerError);

// Login
app.MapPost("/login", async (ToDoDbContext db, LoginRequest loginRequest, ILogger<Program> logger) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(loginRequest.Username) || string.IsNullOrWhiteSpace(loginRequest.Password))
            return Results.BadRequest(new { message = "Username and Password are required" });

        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == loginRequest.Username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
        {
            logger.LogWarning("Failed login attempt for username: {Username}", loginRequest.Username);
            return Results.Unauthorized();
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(jwtKey);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("UserId", user.Id.ToString())
            }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            Issuer = jwtIssuer,
            Audience = jwtAudience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        logger.LogInformation("User logged in: {Username}", user.Username);
        return Results.Ok(new { token = tokenString, username = user.Username, expiresIn = 900, tokenType = "Bearer" });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error during login");
        return Results.StatusCode(500);
    }
})
.WithName("Login")
.AllowAnonymous()
.RequireRateLimiting("login")
.Produces(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status429TooManyRequests)
.Produces(StatusCodes.Status500InternalServerError);

// Get All Tasks (Protected)
app.MapGet("/tasks", async (ToDoDbContext db, ILogger<Program> logger) =>
{
    try
    {
        var tasks = await db.Items.ToListAsync();
        return Results.Ok(tasks);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error fetching tasks");
        return Results.StatusCode(500);
    }
})
.RequireAuthorization()
.WithName("Get All Tasks")
.Produces(StatusCodes.Status200OK)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status500InternalServerError);

// Create Task (Protected)
app.MapPost("/tasks", async (ToDoDbContext db, Item item, ILogger<Program> logger) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(item.Name))
            return Results.BadRequest(new { message = "Task name is required" });

        if (item.Name.Length > 100)
            return Results.BadRequest(new { message = "Task name cannot exceed 100 characters" });

        db.Items.Add(item);
        await db.SaveChangesAsync();

        logger.LogInformation("Task created: {TaskId}", item.Id);
        return Results.Created($"/tasks/{item.Id}", item);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error creating task");
        return Results.StatusCode(500);
    }
})
.RequireAuthorization()
.WithName("Create Task")
.Produces(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status500InternalServerError);

// Update Task (Protected)
app.MapPut("/tasks/{id}", async (int id, ToDoDbContext db, Item updatedItem, ILogger<Program> logger) =>
{
    try
    {
        var item = await db.Items.FindAsync(id);
        if (item is null)
            return Results.NotFound(new { message = $"Task {id} not found" });

        if (string.IsNullOrWhiteSpace(updatedItem.Name))
            return Results.BadRequest(new { message = "Task name is required" });

        if (updatedItem.Name.Length > 100)
            return Results.BadRequest(new { message = "Task name cannot exceed 100 characters" });

        item.Name = updatedItem.Name;
        item.IsComplete = updatedItem.IsComplete;

        await db.SaveChangesAsync();
        logger.LogInformation("Task updated: {TaskId}", id);
        return Results.NoContent();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error updating task");
        return Results.StatusCode(500);
    }
})
.RequireAuthorization()
.WithName("Update Task")
.Produces(StatusCodes.Status204NoContent)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status404NotFound)
.Produces(StatusCodes.Status500InternalServerError);

// Delete Task (Protected)
app.MapDelete("/tasks/{id}", async (int id, ToDoDbContext db, ILogger<Program> logger) =>
{
    try
    {
        var item = await db.Items.FindAsync(id);
        if (item is null)
            return Results.NotFound(new { message = $"Task {id} not found" });

        db.Items.Remove(item);
        await db.SaveChangesAsync();

        logger.LogInformation("Task deleted: {TaskId}", id);
        return Results.NoContent();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error deleting task");
        return Results.StatusCode(500);
    }
})
.RequireAuthorization()
.WithName("Delete Task")
.Produces(StatusCodes.Status204NoContent)
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status404NotFound)
.Produces(StatusCodes.Status500InternalServerError);

app.Run();

// ===== Helper Classes =====

/// <summary>
/// מחלקה עזר ל-Login Request
/// </summary>
public record LoginRequest(string Username, string Password);