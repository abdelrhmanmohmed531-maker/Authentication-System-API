using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using AuthenticationSystemAPI.Configuration;
using AuthenticationSystemAPI.Data;
using AuthenticationSystemAPI.Services;

/*
 * ===================================================================
 * PROGRAM.CS - Application Entry Point and Configuration
 * ===================================================================
 * 
 * This is where we configure all services and the application pipeline.
 * Think of it as the "glue" that connects everything together.
 * 
 * CLEAN ARCHITECTURE LAYERS IN THIS FILE:
 * - Configuration: JWT Settings, Database, Swagger
 * - Services: AuthService (Dependency Injection)
 * - Middleware: Authentication, Authorization, Swagger
 * 
 * FLOW OF CONFIGURATION:
 * 1. Create WebApplication builder
 * 2. Configure services (Dependency Injection container)
 * 3. Build the application
 * 4. Configure middleware pipeline
 * 5. Run the application
 * 
 * DEPENDENCY INJECTION (DI):
 * - ASP.NET Core uses a DI container
 * - Services are registered here and injected where needed
 * - Makes code loosely coupled and testable
 */

var builder = WebApplication.CreateBuilder(args);

/*
 * ===================================================================
 * SECTION 1: ADD SERVICES TO THE CONTAINER
 * ===================================================================
 */

// Add controllers to handle HTTP requests
// This enables MVC pattern with Controllers
builder.Services.AddControllers();

// Add OpenAPI/Swagger for API documentation
// Swashbuckle generates interactive API docs
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

/*
 * ===================================================================
 * DATABASE CONFIGURATION (Entity Framework Core)
 * ===================================================================
 * 
 * Here we configure SQL Server as our database provider
 * 
 * Connection String: Tells EF how to connect to SQL Server
 * - Server: localhost (or your SQL Server name)
 * - Database: AuthDB (will be created if not exists)
 * - TrustServerCertificate: true (for local dev SSL)
 * 
 * Code First Approach:
 * - We define models in C# (User.cs)
 * - EF generates the database schema
 * - Database.EnsureCreated() creates tables automatically
 */
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

/*
 * ===================================================================
 * JWT CONFIGURATION
 * ===================================================================
 * 
 * We read JWT settings from appsettings.json
 * and register JwtSettings as a singleton service
 */
var jwtSettings = new JwtSettings
{
    SecretKey = builder.Configuration["Jwt:SecretKey"] ?? "DefaultSecretKeyForDevelopment123!",
    Issuer = builder.Configuration["Jwt:Issuer"] ?? "AuthAPI",
    Audience = builder.Configuration["Jwt:Audience"] ?? "AuthAPIUsers",
    ExpirationMinutes = int.Parse(builder.Configuration["Jwt:ExpirationMinutes"] ?? "60")
};

builder.Services.AddSingleton(jwtSettings);

/*
 * ===================================================================
 * JWT BEARER AUTHENTICATION
 * ===================================================================
 * 
 * This configures JWT Bearer token authentication.
 * When a request comes in with an Authorization header:
 * 1. Extract the token from "Bearer <token>"
 * 2. Validate the token signature using SecretKey
 * 3. Check if token is expired
 * 4. Create a ClaimsPrincipal with user claims
 * 5. Set HttpContext.User for use in controllers
 */
builder.Services.AddAuthentication(options =>
{
    // Default scheme for authentication
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    
    // Default scheme for challenge (when unauthorized)
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Configure token validation parameters
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Validate the server that created the token
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,

        // Validate who the token is for
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,

        // Validate token expiration
        ValidateLifetime = true,

        // Validate the signing key
        ValidateIssuerSigningKey = true,
        
        // The secret key used to sign tokens
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
    };
});

/*
 * ===================================================================
 * AUTHORIZATION POLICIES
 * ===================================================================
 * 
 * Configure authorization rules
 * Here we can define policies like "AdminOnly", "AtLeast18", etc.
 */
builder.Services.AddAuthorization();

/*
 * ===================================================================
 * REGISTER APPLICATION SERVICES
 * ===================================================================
 * 
 * Here we register our custom services for Dependency Injection
 * 
 * Scoped vs Singleton vs Transient:
 * - Scoped: Created once per request (most common for DbContext)
 * - Singleton: Created once for entire application lifetime
 * - Transient: Created each time it's requested
 */
builder.Services.AddScoped<IAuthService, AuthService>();

/*
 * ===================================================================
 * SWAGGER CONFIGURATION WITH JWT SECURITY
 * ===================================================================
 * 
 * This adds JWT authentication to Swagger UI
 * Allows you to test protected endpoints directly from Swagger
 */
builder.Services.AddSwaggerGen(c =>
{
    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.\r\n\r\nExample: \"Bearer 12345abcdef\"",
        Name = "Authorization", // Header parameter name
        In = ParameterLocation.Header, // Where to put the token
        Type = SecuritySchemeType.ApiKey, // Type of security scheme
        Scheme = "Bearer" // Authentication scheme
    });

    // Make Swagger use this security scheme
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
            Array.Empty<string>() // No specific scopes required
        }
    });
});

/*
 * ===================================================================
 * SECTION 2: BUILD THE APPLICATION
 * ===================================================================
 */
var app = builder.Build();

/*
 * ===================================================================
 * SECTION 3: CONFIGURE THE HTTP REQUEST PIPELINE
 * ===================================================================
 * 
 * This is the middleware pipeline - each request passes through
 * these components in order:
 */

// Configure the Swagger/OpenAPI pipeline
if (app.Environment.IsDevelopment())
{
    // In development, show Swagger UI
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        // Customize Swagger UI endpoint
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API v1");
        
        // Enable OAuth2 in Swagger UI (optional - for more advanced auth)
        // c.OAuthClientId("swagger");
        // c.OAuthAppName("Auth API");
    });
}

/*
 * ===================================================================
 * DATABASE INITIALIZATION
 * ===================================================================
 * 
 * Ensure the database is created and migrations are applied
 * In development, this creates tables from our models
 * 
 * IMPORTANT: In production, use migrations instead!
 * dotnet ef migrations add InitialCreate
 * dotnet ef database update
 */
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    
    // This creates the database if it doesn't exist
    // And creates tables based on our model definitions
    context.Database.EnsureCreated();
}

/*
 * ===================================================================
 * MIDDLEWARE REGISTRATION
 * ===================================================================
 */

// Redirect HTTP to HTTPS (uncomment for production)
// app.UseHttpsRedirection();

/*
 * ===================================================================
 * AUTHENTICATION & AUTHORIZATION MIDDLEWARE
 * ===================================================================
 * 
 * ORDER MATTERS! These must be in this order:
 * 1. UseAuthentication - Validates JWT tokens
 * 2. UseAuthorization - Checks [Authorize] attributes
 * 
 * If you swap these, [Authorize] won't work properly!
 */

// Enables JWT Bearer authentication
// Reads Authorization header, validates token, creates User principal
app.UseAuthentication();

// Enforces [Authorize] attributes on controllers/actions
app.UseAuthorization();

// Map controllers to routes
app.MapControllers();

/*
 * ===================================================================
 * START THE APPLICATION
 * ===================================================================
 */
app.Run();

