using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using AuthenticationSystemAPI.Configuration;
using AuthenticationSystemAPI.Data;
using AuthenticationSystemAPI.DTOs;
using AuthenticationSystemAPI.Models;
using BCrypt.Net;

/*
 * ===================================================================
 * AUTHENTICATION SERVICE - Business Logic Layer
 * ===================================================================
 * 
 * Clean Architecture - This is the "Application" or "Service" layer:
 * - Contains business logic and rules
 * - Depends on Data layer (DbContext)
 * - Depends on Configuration (JWT settings)
 * - Returns DTOs, not Entities (security!)
 * 
 * TWO CLASSES PATTERN:
 * 1. IAuthService (Interface) - Contract defining what the service does
 *    - Enables dependency injection
 *    - Makes code testable (can mock the interface)
 * 
 * 2. AuthService (Implementation) - Actual logic
 *    - Implements IAuthService
 *    - Contains all authentication business rules
 * 
 * FLOW OF AUTHENTICATION:
 * 1. User sends credentials to API
 * 2. Controller receives request, calls AuthService
 * 3. AuthService validates, hashes/verifies password
 * 4. AuthService generates JWT token
 * 5. AuthService returns response (token + user info)
 * 6. Controller returns response to client
 * 7. Client includes token in future requests
 */

namespace AuthenticationSystemAPI.Services;

/*
 * INTERFACE - Defines the contract
 * --------------------------------
 * Think of it as a specification or promise:
 * "Any class implementing this must have these methods"
 * 
 * Benefits:
 * - Loose coupling: Controller doesn't need to know HOW it works
 * - Testability: Can create mock implementations for testing
 * - Flexibility: Can change implementation without breaking callers
 */
public interface IAuthService
{
    // Register a new user
    // Returns AuthResponse with token if successful, null if failed
    Task<AuthResponse?> RegisterAsync(RegisterRequest request);

    // Authenticate existing user
    // Returns AuthResponse with token if credentials valid, null if invalid
    Task<AuthResponse?> LoginAsync(LoginRequest request);

    // Get user profile (for protected endpoints)
    // Returns user data if found, null if not
    Task<UserDto?> GetProfileAsync(string username);
}

/*
 * IMPLEMENTATION - Actual business logic
 * --------------------------------------
 * This is where the magic happens!
 * 
 * Key responsibilities:
 * 1. Validate input data
 * 2. Check for duplicates (username/email)
 * 3. Hash passwords (registration) / Verify passwords (login)
 * 4. Generate JWT tokens
 * 5. Return appropriate responses
 */
public class AuthService : IAuthService
{
    // Dependency Injection - We need these services
    // Private readonly ensures they can't be changed after construction
    
    private readonly AppDbContext _context;      // Database access
    private readonly JwtSettings _jwtSettings;  // JWT configuration

    /*
     * Constructor - Receives dependencies via DI
     * ----------------------------------------
     * ASP.NET Core's DI container will automatically provide:
     * - AppDbContext (registered in Program.cs)
     * - JwtSettings (registered in Program.cs)
     * 
     * This is called "Constructor Injection"
     */
    public AuthService(AppDbContext context, JwtSettings jwtSettings)
    {
        _context = context;
        _jwtSettings = jwtSettings;
    }

    /*
     * REGISTER METHOD
     * ---------------
     * Step 1: Validate input
     * Step 2: Check if username/email already exists
     * Step 3: Hash password using BCrypt
     * Step 4: Create User entity
     * Step 5: Save to database
     * Step 6: Generate JWT token
     * Step 7: Return response
     */
    public async Task<AuthResponse?> RegisterAsync(RegisterRequest request)
    {
        // STEP 1: Validate input (basic check - controller should also validate)
        if (string.IsNullOrWhiteSpace(request.Username) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return null; // Return null to indicate failure
        }

        // STEP 2: Check for duplicate username
        // .AnyAsync() generates: SELECT CASE WHEN EXISTS(...) THEN 1 ELSE 0 END
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
        {
            // Username already taken
            return null;
        }

        // STEP 2b: Check for duplicate email
        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
        {
            // Email already registered
            return null;
        }

        // STEP 3: Hash the password
        // BCrypt is a slow hashing algorithm designed for passwords
        // - Adds random salt automatically
        // - Work factor controls computation time (default = 10)
        // - Much safer than MD5, SHA1, or SHA256 for passwords
        // 
        // Example: "password123" becomes "$2a$10$abcdefghijklmnopqrstuv..."
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

        // STEP 4: Create User entity
        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = passwordHash,
            Role = "User", // Default role - could be changed based on logic
            CreatedAt = DateTime.UtcNow
        };

        // STEP 5: Save to database
        // .Add() queues the INSERT operation
        // .SaveChangesAsync() actually executes it
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // STEP 6: Generate JWT token
        var token = GenerateJwtToken(user);

        // STEP 7: Return success response
        return new AuthResponse
        {
            Token = token,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes)
        };
    }

    /*
     * LOGIN METHOD
     * -----------
     * Step 1: Find user by username
     * Step 2: Verify password against stored hash
     * Step 3: Generate JWT token
     * Step 4: Return response
     */
    public async Task<AuthResponse?> LoginAsync(LoginRequest request)
    {
        // STEP 1: Find the user
        // .FirstOrDefaultAsync() returns null if not found
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        // If user doesn't exist, return null (don't reveal this to attacker)
        if (user == null)
        {
            return null;
        }

        // STEP 2: Verify password
        // BCrypt.Net.BCrypt.Verify() compares:
        // - Plain text password from request
        // - Hash stored in database
        // 
        // IMPORTANT: Even if user is not found, we should still "check" a hash
        // This prevents timing attacks where attacker measures response time
        bool isPasswordValid = BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash);

        if (!isPasswordValid)
        {
            // Wrong password - return null
            return null;
        }

        // STEP 3: Generate JWT token
        var token = GenerateJwtToken(user);

        // STEP 4: Return success response
        return new AuthResponse
        {
            Token = token,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes)
        };
    }

    /*
     * GET PROFILE METHOD
     * ------------------
     * Used by protected endpoints to get current user info
     */
    public async Task<UserDto?> GetProfileAsync(string username)
    {
        // Find user by username
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

        if (user == null)
        {
            return null;
        }

        // Map Entity to DTO (excludes sensitive data like PasswordHash)
        return new UserDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role,
            CreatedAt = user.CreatedAt
        };
    }

    /*
     * JWT TOKEN GENERATION
     * --------------------
     * This creates the security token that authenticates users
     * 
     * JWT Structure (3 parts separated by dots):
     * - Header: Algorithm and token type
     * - Payload: Claims (user data)
     * - Signature: Verifies token wasn't tampered with
     * 
     * Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIi...
     */
    private string GenerateJwtToken(User user)
    {
        // STEP 1: Create security key from secret
        // SymmetricKey means same key for signing and verifying
        // This key was configured in appsettings.json
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));

        // STEP 2: Create signing credentials
        // HMAC-SHA256 is the algorithm used to create the signature
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // STEP 3: Create claims (payload data)
        // Claims are statements about the user
        // They are encoded in the JWT and can be read by the application
        var claims = new[]
        {
            // NameIdentifier: Unique user ID (commonly used)
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            
            // Name: Username (commonly used for display)
            new Claim(ClaimTypes.Name, user.Username),
            
            // Email: User's email
            new Claim(ClaimTypes.Email, user.Email),
            
            // Role: User's role for authorization
            new Claim(ClaimTypes.Role, user.Role),

            // Custom claim: When token was issued
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // STEP 4: Create the token
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,           // Who created the token
            audience: _jwtSettings.Audience,       // Who the token is for
            claims: claims,                         // User data
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes), // Expiration
            signingCredentials: credentials         // Signature
        );

        // STEP 5: Write token to string
        // This is what the client receives and stores
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

