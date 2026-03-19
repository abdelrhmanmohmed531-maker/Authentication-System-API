namespace AuthenticationSystemAPI.DTOs;

/*
 * ===================================================================
 * DATA TRANSFER OBJECTS (DTOs) - Data carriers between layers
 * ===================================================================
 * 
 * Why use DTOs instead of exposing Entity models directly?
 * 
 * 1. SECURITY: 
 *    - Entities may contain sensitive data (PasswordHash)
 *    - DTOs let us control exactly what data is exposed to clients
 *    - Prevents over-posting attacks (client sending extra fields)
 * 
 * 2. VERSIONING:
 *    - Can change internal structure without breaking API contracts
 *    - Different endpoints can return different DTOs
 * 
 * 3. VALIDATION:
 *    - DTOs can have validation attributes
 *    - Separation of concerns: Model = data, DTO = transport
 */

/*
 * REGISTER REQUEST DTO
 * -------------------
 * Data we expect from client when registering a new user.
 * 
 * Flow: Client → Controller → Service → Database
 */
public class RegisterRequest
{
    // Username: Required, 3-50 characters
    // [Required] attribute ensures model validation fails if empty
    public string Username { get; set; } = string.Empty;

    // Email: Required, valid email format
    // We'll validate format in the service layer too
    public string Email { get; set; } = string.Empty;

    // Password: Required, minimum security requirements
    // Should be at least 6 characters
    public string Password { get; set; } = string.Empty;
}

/*
 * LOGIN REQUEST DTO
 * ----------------
 * Data we expect from client when logging in.
 * 
 * Flow: Client → Controller → Service → Validate → Generate JWT
 */
public class LoginRequest
{
    // Username - used to identify the account
    public string Username { get; set; } = string.Empty;

    // Password - verified against stored hash
    public string Password { get; set; } = string.Empty;
}

/*
 * AUTH RESPONSE DTO
 * ----------------
 * Data we send back to client after successful registration/login.
 * 
 * This is what the client receives:
 * - Token: JWT for subsequent API calls
 * - UserInfo: Basic profile data for UI display
 */
public class AuthResponse
{
    // JWT Token - This is the "key" the client uses
    // Must be included in Authorization header for protected endpoints:
    // Authorization: Bearer <token>
    public string Token { get; set; } = string.Empty;

    // Username - for UI display
    public string Username { get; set; } = string.Empty;

    // Email - for UI display and contact
    public string Email { get; set; } = string.Empty;

    // Role - for UI authorization (show/hide admin features)
    public string Role { get; set; } = string.Empty;

    // Token expiration time - helps client know when to re-login
    public DateTime ExpiresAt { get; set; }
}

/*
 * USER PROFILE DTO
 * ---------------
 * Public user information - excludes sensitive data
 * Used for profile endpoints visible to authenticated users
 */
public class UserDto
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

/*
 * ERROR RESPONSE DTO
 * ------------------
 * Standard error format for all API errors
 * 
 * Benefits:
 * - Consistent error format across all endpoints
 * - Easy for clients to parse and display errors
 * - Includes error code for programmatic handling
 */
public class ErrorResponse
{
    // Human-readable error message
    public string Message { get; set; } = string.Empty;

    // Optional: Error code for client-side handling
    public string? Code { get; set; }

    // Optional: Additional details for debugging
    public string? Details { get; set; }
}

